"""Report rendering.

Turns a Report (+ its Findings + branding) into a render context for the
Jinja2 templates in ``templates/render/``. Rendering is deterministic and
rule-based: no LLM calls in the happy path.

The output is a dict passed to a Jinja2 template; the template decides the
final document structure (Pentest anchor = ``pentest/report.html.j2``).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from ..models.finding import Severity
from .branding import SEVERITY_COLORS, load_branding
from ..core import config
from .smart_context import SmartContext


def _sev_label(sev: str) -> str:
    return sev.lower()


def _sev_color(sev: str) -> str:
    return SEVERITY_COLORS.get(_sev_label(sev), "#666666")


def group_by_severity(findings: list) -> dict[str, list]:
    """Order findings inside groups high->critical, keeping severity order."""
    buckets = {s.value: [] for s in Severity}
    for f in findings:
        sev = _sev_label(f.severity)
        if sev not in buckets:
            sev = Severity.MEDIUM.value
        buckets[sev].append(f)
    for sev, items in buckets.items():
        items.sort(key=lambda f: f.title.lower())
    return buckets


def stats(findings: list) -> dict[str, list]:
    """Counts per severity + totals, ordered critical downward."""
    grouped = group_by_severity(findings)
    counts = {sev: len(items) for sev, items in grouped.items()}
    return {
        "counts": counts,
        "total": len(findings),
        # order for the table/legend: critical first
        "ordered": [s.value for s in Severity if counts.get(s.value)],
    }


def exec_summary_text(report, counts: dict[str, int]) -> str:
    """Deterministic one-paragraph executive summary.

    Written to be spoken to a non-technical reader first (the find a,
    the risk, the fix), per the '3 readers' house model.
    """
    total = counts.get("total", 0)
    critical = counts.get("counts", {}).get(Severity.CRITICAL.value, 0)
    high = counts.get("counts", {}).get(Severity.HIGH.value, 0)

    if total == 0:
        base = (
            f"{report.client}: pentest zakończony bez znalezionych podatności "
            "w testowanym zakresie"
        )
    else:
        base = (
            f"{report.client}: zidentyfikowano {total} podatności "
            f"({critical} krytycznych, {high} wysokich) w zakresie "
            f"testu bezpieczeństwa"
        )
    return base


def build_context(report, findings, branding_ref: str = "default") -> dict[str, Any]:
    branding = load_branding(branding_ref)
    grouped = group_by_severity(findings)
    st = stats(findings)

    rows = []
    for sev in ["critical", "high", "medium", "low", "info"]:
        rows.append(
            {
                "severity": sev,
                "label": sev.upper(),
                "color": _sev_color(sev),
                "count": st["counts"].get(sev, 0),
            }
        )

    # user-typed exec summary wins; fall back to the generated one
    summary = report.summary.strip() or exec_summary_text(report, st)

    smart = SmartContext().build(report, findings)

    return {
        "report": report,
        "branding": branding,
        "findings": findings,
        "grouped": grouped,
        "stats": st,
        "severity_rows": rows,
        "summary": summary,
        "smart": smart,
        "generator": f"ReportForge (legacy build)",
    }


# ------------------------------------------------------------- Jinja2 hook ---

from jinja2 import Environment, FileSystemLoader  # noqa: E402


def _env() -> Environment:
    loader = FileSystemLoader(str(config.RENDER_TEMPLATES_DIR))
    return Environment(loader=loader, autoescape=True)


def render_html(report, findings, branding_ref: str = "default") -> str:
    context = build_context(report, findings, branding_ref)
    env = _env()
    template = env.get_template(f"{report.template_type}/report.html.j2")
    return template.render(**context)