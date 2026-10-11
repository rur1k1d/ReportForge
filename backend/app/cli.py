"""Headless CLI for ReportForge.

Talk directly to the same services the web app uses (ingest, renderer,
exporter, smart_context) via a SQLAlchemy session — no HTTP server needed.

Entry point:  python -m app.cli [command] ...   (launcher: bin/reportforge)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core.database import SessionLocal, init_db
from .models import Finding, Report
from .services import exporter
from .services.branding import available_branding
from .services.ingest import parse_findings
from .services.smart_context import SmartContext


def _session():
    init_db()
    return SessionLocal()


def _load_report(db, report_id: int) -> Report:
    report = db.get(Report, report_id)
    if report is None:
        print(f"report not found: {report_id}", file=sys.stderr)
        sys.exit(1)
    return report


def cmd_list(db, args) -> int:
    q = db.query(Report).order_by(Report.updated_at.desc())
    if args.status:
        q = q.filter(Report.status == args.status)
    for r in q.all():
        total = len(r.findings)
        sev = {}
        for f in r.findings:
            sev[f.severity] = sev.get(f.severity, 0) + 1
        summary = ", ".join(f"{k.upper()} {v}" for k, v in sev.items()) or "no findings"
        print(f"#{r.id}\t[{r.status}]\t{r.title}\tclient={r.client}\t"
              f"template={r.template_type}\t{total} findings ({summary})")
    return 0


def cmd_create(db, args) -> int:
    report = Report(
        title=args.title,
        template_type=args.template,
        client=args.client,
        scope=args.scope,
        version=args.version,
        branding_ref=args.branding,
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    print(f"created report #{report.id}: {report.title}")
    return 0


def cmd_import(db, args) -> int:
    report = _load_report(db, args.report)
    if args.file:
        content = Path(args.file).read_text(encoding="utf-8")
    else:
        content = sys.stdin.read()
    try:
        raw, context = parse_findings(content, args.src, args.label)
    except ValueError as exc:
        print(f"import failed: {exc}", file=sys.stderr)
        return 1

    raw = list(raw)
    imported = 0
    seen = {(f.title.strip().lower(), (f.asset or "").strip().lower())
            for f in report.findings} if args.dedupe else set()
    for rf in raw:
        key = (rf.title.strip().lower(), (rf.asset or "").strip().lower())
        if args.dedupe and key in seen:
            continue
        seen.add(key)
        db.add(Finding(
            report=report,
            title=rf.title,
            severity=rf.canonical_severity(),
            cvss=rf.cvss,
            description=rf.description,
            impact=rf.impact,
            recommendation=rf.recommendation,
            evidence=rf.evidence,
            cwe=rf.cwe,
            cve=rf.cve,
            mitre=rf.mitre,
            asset=rf.asset,
            source=rf.source,
        ))
        imported += 1
    db.commit()
    skipped = len(raw) - imported
    msg = f"imported {imported} finding(s) into report #{report.id}"
    if skipped:
        msg += f" ({skipped} duplicate(s) skipped)"
    print(msg)
    if context:
        print(f"context: {json.dumps(context, ensure_ascii=False)[:200]}")
    return 0


def cmd_render(db, args) -> int:
    report = _load_report(db, args.report)
    html = exporter.render_html(report, list(report.findings), args.branding)
    sys.stdout.write(html)
    return 0


def cmd_export(db, args) -> int:
    report = _load_report(db, args.report)
    findings = list(report.findings)
    out = Path(args.out)
    if args.format == "html":
        exporter.export_html(report, findings, out, args.branding)
    elif args.format == "pdf":
        exporter.export_pdf(report, findings, out, args.branding)
    elif args.format == "docx":
        exporter.export_docx(report, findings, out, args.branding)
    elif args.format == "md":
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(exporter.render_markdown(report, findings, args.branding),
                       encoding="utf-8")
    else:
        print(f"unsupported format: {args.format}", file=sys.stderr)
        return 1
    print(f"exported -> {out}")
    return 0


def cmd_smart(db, args) -> int:
    report = _load_report(db, args.report)
    ctx = SmartContext().build_and_persist(report, list(report.findings), db)
    print(json.dumps(ctx, ensure_ascii=False, indent=2, default=str))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="reportforge",
                                description="Self-hosted security report generator — headless CLI.")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("list", help="list reports")
    sp.add_argument("--status", default=None, help="filter by status (draft|ready|final)")
    sp.set_defaults(func=cmd_list)

    sp = sub.add_parser("create", help="create a new report")
    sp.add_argument("--title", required=True)
    sp.add_argument("--client", required=True)
    sp.add_argument("--template", default="pentest", choices=["pentest", "va"])
    sp.add_argument("--scope", default="")
    sp.add_argument("--version", default="v0.2")
    sp.add_argument("--branding", default="default")
    sp.set_defaults(func=cmd_create)

    sp = sub.add_parser("import", help="import findings into a report")
    sp.add_argument("--report", type=int, required=True)
    sp.add_argument("--src", default="auto",
                    choices=["auto", "yaml", "nuclei", "bb_workflow", "burp"])
    sp.add_argument("--file", default=None, help="read from a file instead of stdin")
    sp.add_argument("--label", default="")
    sp.add_argument("--dedupe", action="store_true")
    sp.set_defaults(func=cmd_import)

    sp = sub.add_parser("render", help="render report HTML to stdout")
    sp.add_argument("--report", type=int, required=True)
    sp.add_argument("--branding", default="default")
    sp.set_defaults(func=cmd_render)

    sp = sub.add_parser("export", help="export a report to a file")
    sp.add_argument("--report", type=int, required=True)
    sp.add_argument("--format", required=True, choices=["html", "pdf", "docx", "md"])
    sp.add_argument("--out", required=True)
    sp.add_argument("--branding", default="default")
    sp.set_defaults(func=cmd_export)

    sp = sub.add_parser("smart", help="compute and cache smart context")
    sp.add_argument("--report", type=int, required=True)
    sp.set_defaults(func=cmd_smart)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    db = _session()
    try:
        return args.func(db, args)
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())