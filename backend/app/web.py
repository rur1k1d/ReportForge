"""Web UI routes (Jinja2 SSR pages).

These are thin HTML wrappers over the JSON API. Small pages do direct DB work
via get_session; exports reuse the same exporter used by the JSON routes.
"""

from __future__ import annotations

import tempfile
from collections import Counter
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.background import BackgroundTasks
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from jinja2 import Environment, FileSystemLoader
from sqlalchemy.orm import Session

from .core import config
from .core.database import get_session
from .models import Finding, Report
from .services import exporter
from .services.branding import available_branding
from .services.ingest import parse_findings
from .services.smart_context import SmartContext

router = APIRouter()
Db = Annotated[Session, Depends(get_session)]


def _env() -> Environment:
    loader = FileSystemLoader(str(config.APP_DIR / "app" / "templates" / "web"))
    return Environment(loader=loader, autoescape=True)


def _page(template: str, request: Request, **ctx):
    env = _env()
    t = env.get_template(template)
    return HTMLResponse(t.render(request=request, **ctx))


def _get_report(db: Db, report_id: int) -> Report:
    report = db.get(Report, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="report not found")
    return report


def _finding_keys(report: Report) -> set[tuple[str, str]]:
    """Existing (title, asset) pairs for de-duplication."""
    return {
        (f.title.strip().lower(), (f.asset or "").strip().lower())
        for f in report.findings
    }


def _findings_summary(findings: list) -> dict:
    """Quick severity buckets for list views."""
    buckets = Counter(f.severity for f in findings)
    return {
        "total": len(findings),
        "critical": buckets.get("critical", 0),
        "high": buckets.get("high", 0),
        "medium": buckets.get("medium", 0),
        "low": buckets.get("low", 0),
        "info": buckets.get("info", 0),
    }


# ------------------------------------------------------------------ pages ---

@router.get("/", response_class=HTMLResponse)
def index(db: Db, request: Request):
    reports = db.query(Report).order_by(Report.updated_at.desc()).all()
    rows = [
        {
            "id": r.id,
            "title": r.title,
            "client": r.client,
            "template_type": r.template_type,
            "status": r.status,
            "version": r.version,
            "updated_at": r.updated_at,
            "findings": _findings_summary(list(r.findings)),
        }
        for r in reports
    ]
    return _page("index.html.j2", request, reports=rows, branding_names=available_branding())


@router.get("/reports/new", response_class=HTMLResponse)
def new_report(request: Request):
    return _page("new.html.j2", request, branding_names=available_branding())


@router.post("/reports/new")
def create_report(
    db: Db,
    title: str = Form(...),
    template_type: str = Form("pentest"),
    client: str = Form(""),
    scope: str = Form(""),
    version: str = Form("v0.1"),
):
    report = Report(
        title=title,
        template_type=template_type,
        client=client,
        scope=scope,
        version=version,
    )
    db.add(report)
    db.commit()
    return RedirectResponse(f"/reports/{report.id}", status_code=303)


@router.get("/reports/{report_id}", response_class=HTMLResponse)
def edit_report(report_id: int, db: Db, request: Request):
    report = _get_report(db, report_id)
    return _page(
        "edit.html.j2",
        request,
        report=report,
        findings=list(report.findings),
        branding_names=available_branding(),
    )


@router.post("/reports/{report_id}", response_class=HTMLResponse)
def update_report(
    report_id: int,
    db: Db,
    request: Request,
    title: str = Form(...),
    client: str = Form(""),
    scope: str = Form(""),
    summary: str = Form(""),
    methodology: str = Form(""),
    status: str = Form("draft"),
    version: str = Form("v0.1"),
    branding_ref: str = Form("default"),
):
    report = _get_report(db, report_id)
    report.title = title
    report.client = client
    report.scope = scope
    report.summary = summary
    report.methodology = methodology
    report.status = status
    report.version = version
    report.branding_ref = branding_ref
    db.commit()
    return _page(
        "edit.html.j2",
        request,
        report=report,
        findings=list(report.findings),
        branding_names=available_branding(),
        saved_note=f"Report updated ({version}).",
    )


# ----------------------------------------------------------------- import ---

@router.post("/reports/{report_id}/import", response_class=HTMLResponse)
def import_page(
    report_id: int,
    db: Db,
    request: Request,
    source_type: str = Form("auto"),
    content: str = Form(...),
    source_label: str = Form(""),
    dedupe: bool = Form(False),
):
    report = _get_report(db, report_id)
    note = ""
    try:
        raw, _context = parse_findings(content, source_type, source_label)
    except ValueError as exc:
        raw = []
        note = f"Import failed: {exc}"
    existing_keys = _finding_keys(report) if dedupe else set()
    dupes_skipped = 0
    for rf in raw:
        key = (
            rf.title.strip().lower(),
            (rf.asset or "").strip().lower(),
        )
        if key in existing_keys:
            dupes_skipped += 1
            continue
        existing_keys.add(key)
        db.add(Finding(
            report=report,
            title=rf.title,
            severity=rf.canonical_severity(),
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
    added = len(raw) - dupes_skipped
    if added and not note:
        note = f"Imported {added} finding(s)"
        if dupes_skipped:
            note += f" ({dupes_skipped} duplicate(s) skipped)"
        note += "."
    elif not added and not note:
        note = "Nothing imported. All findings already present (dedupe on)."
    db.commit()
    return _page(
        "edit.html.j2",
        request,
        report=report,
        findings=list(report.findings),
        branding_names=available_branding(),
        note=note,
    )


# ------------------------------------------------------------- findings CRUD --

@router.post("/reports/{report_id}/findings/add", response_class=HTMLResponse)
def add_finding_web(
    report_id: int,
    db: Db,
    request: Request,
    title: str = Form(...),
    severity: str = Form("medium"),
    asset: str = Form(""),
    cwe: str = Form(""),
    description: str = Form(""),
    impact: str = Form(""),
    recommendation: str = Form(""),
    evidence: str = Form(""),
):
    report = _get_report(db, report_id)
    db.add(Finding(
        report=report,
        title=title.strip(),
        severity=severity,
        asset=asset.strip(),
        cwe=cwe.strip(),
        description=description,
        impact=impact,
        recommendation=recommendation,
        evidence=evidence,
        source="manual",
    ))
    db.commit()
    return RedirectResponse(f"/reports/{report.id}#findings", status_code=303)


@router.post("/findings/{finding_id}/update", response_class=HTMLResponse)
def update_finding_web(
    finding_id: int,
    db: Db,
    request: Request,
    title: str = Form(...),
    severity: str = Form("medium"),
    asset: str = Form(""),
    cwe: str = Form(""),
    description: str = Form(""),
    impact: str = Form(""),
    recommendation: str = Form(""),
    evidence: str = Form(""),
):
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    finding.title = title.strip()
    finding.severity = severity
    finding.asset = asset.strip()
    finding.cwe = cwe.strip()
    finding.description = description
    finding.impact = impact
    finding.recommendation = recommendation
    finding.evidence = evidence
    db.commit()
    return RedirectResponse(f"/reports/{finding.report_id}#findings", status_code=303)


@router.post("/findings/{finding_id}/delete")
def delete_finding_web(finding_id: int, db: Db):
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    report_id = finding.report_id
    db.delete(finding)
    db.commit()
    return RedirectResponse(f"/reports/{report_id}#findings", status_code=303)


# ----------------------------------------------------------------- export ---

@router.get("/reports/{report_id}/export")
def export_web(report_id: int, db: Db, fmt: str = "html"):
    report = _get_report(db, report_id)
    findings = list(report.findings)
    out = Path(tempfile.mkstemp(suffix=f".{fmt}")[1])
    cleanup = BackgroundTasks()
    cleanup.add_task(out.unlink, missing_ok=True)

    if fmt == "html":
        exporter.export_html(report, findings, out)
        return FileResponse(str(out), media_type="text/html; charset=utf-8",
                            filename=f"{report.title.replace(' ', '_')}.html",
                            background=cleanup)
    if fmt == "pdf":
        exporter.export_pdf(report, findings, out)
        return FileResponse(str(out), media_type="application/pdf",
                            filename=f"{report.title.replace(' ', '_')}.pdf",
                            background=cleanup)
    if fmt == "docx":
        exporter.export_docx(report, findings, out)
        return FileResponse(
            str(out),
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            filename=f"{report.title.replace(' ', '_')}.docx",
            background=cleanup)
    raise HTTPException(status_code=400, detail="unsupported format")


# --------------------------------------------------------------- smart ctx ---

@router.post("/reports/{report_id}/smart-context", response_class=HTMLResponse)
def smart_web(report_id: int, db: Db, request: Request):
    report = _get_report(db, report_id)
    ctx = SmartContext().build(report, list(report.findings))
    return _page(
        "edit.html.j2",
        request,
        report=report,
        findings=list(report.findings),
        branding_names=available_branding(),
        smart=ctx,
    )


@router.post("/reports/{report_id}/delete")
def delete_report(report_id: int, db: Db):
    report = _get_report(db, report_id)
    db.delete(report)
    db.commit()
    return RedirectResponse("/", status_code=303)