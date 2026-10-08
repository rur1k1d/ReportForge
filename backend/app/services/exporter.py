"""Exporters: render a report to PDF (WeasyPrint), DOCX (python-docx),
and save the raw HTML for browser review.

PDF output is generated from the same Jinja2 HTML template used for preview,
so the two never drift apart.
"""

from __future__ import annotations

from pathlib import Path

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Pt, RGBColor

from . import renderer
from .branding import SEVERITY_COLORS


def _rgb(hex_color: str) -> RGBColor:
    """'#B22222' -> RGBColor. Falls back to grey for bad input."""
    hex_color = hex_color.lstrip("#")
    if len(hex_color) != 6:
        return RGBColor(0x66, 0x66, 0x66)
    try:
        return RGBColor(int(hex_color[0:2], 16),
                        int(hex_color[2:4], 16),
                        int(hex_color[4:6], 16))
    except ValueError:
        return RGBColor(0x66, 0x66, 0x66)


def _write(path: Path, data: bytes | str, binary: bool = True) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = "wb" if binary else "w"
    kwargs = {} if binary else {"encoding": "utf-8"}
    if isinstance(data, str):
        mode = "w"
        kwargs = {"encoding": "utf-8"}
    with open(path, mode, **kwargs) as fh:
        fh.write(data)
    return path


def render_html(report, findings, branding_ref: str = "default") -> str:
    return renderer.render_html(report, findings, branding_ref)


def export_pdf(report, findings, out: Path, branding_ref: str = "default") -> Path:
    """Render HTML then convert via WeasyPrint to a PDF file."""
    from weasyprint import HTML

    html = render_html(report, findings, branding_ref)
    out.parent.mkdir(parents=True, exist_ok=True)
    HTML(string=html).write_pdf(str(out))
    return out


def export_docx(report, findings, out: Path, branding_ref: str = "default") -> Path:
    """Minimal, dependency-light DOCX via python-docx.

    Not a pixel-perfect copy of the HTML: it produces the editable document
    structure clients actually ask for (title, exec summary, findings list).
    """
    doc = Document()
    title = doc.add_heading(report.title or "Pentest Report", level=0)
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER

    doc.add_paragraph(f"Client: {report.client}")
    doc.add_paragraph(f"Scope: {report.scope or '—'}")

    doc.add_heading("Executive Summary", level=1)
    doc.add_paragraph(report.summary or renderer.exec_summary_text(
        report, renderer.stats(findings)))

    doc.add_heading("Findings", level=1)
    for f in findings:
        p = doc.add_heading(f.title, level=2)
        color = _rgb(SEVERITY_COLORS.get(f.severity, "#666666"))
        p.runs[0].font.color.rgb = color
        meta = doc.add_paragraph()
        meta.add_run(f"Severity: {f.severity.upper()}")
        if f.cwe:
            meta.add_run(f"  CWE: {f.cwe}")
        if f.asset:
            meta.add_run(f"  Asset: {f.asset}")
        if f.description:
            doc.add_paragraph(f"Description: {f.description}")
        if f.impact:
            doc.add_paragraph(f"Impact: {f.impact}")
        if f.recommendation:
            doc.add_paragraph(f"Recommendation: {f.recommendation}")

    out.parent.mkdir(parents=True, exist_ok=True)
    doc.save(str(out))
    return out


def export_html(report, findings, out: Path, branding_ref: str = "default") -> Path:
    """Write the rendered HTML to disk (static view / pandoc input)."""
    html = render_html(report, findings, branding_ref)
    return _write(out, html)