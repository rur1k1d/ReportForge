"""FastAPI routes: reports CRUD, findings CRUD, import, export."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..core.database import get_session
from ..models import Finding, Report
from ..services import exporter
from ..services.ingest import dedupe_raw, existing_keys, parse_findings
from ..services.smart_context import SmartContext
from . import schemas

router = APIRouter()
Db = Annotated[Session, Depends(get_session)]


def _get_report(db: Db, report_id: int) -> Report:
    report = db.get(Report, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="report not found")
    return report


# ------------------------------------------------------------------ reports

@router.get("/reports", response_model=list[schemas.ReportOut])
def list_reports(db: Db, status: Optional[str] = None):
    q = db.query(Report).order_by(Report.updated_at.desc())
    if status:
        q = q.filter(Report.status == status)
    return q.all()


@router.post("/reports", response_model=schemas.ReportOut, status_code=201)
def create_report(payload: schemas.ReportIn, db: Db):
    report = Report(**payload.model_dump())
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


@router.get("/reports/{report_id}", response_model=schemas.ReportOut)
def get_report(report_id: int, db: Db):
    return _get_report(db, report_id)


@router.put("/reports/{report_id}", response_model=schemas.ReportOut)
def update_report(report_id: int, payload: schemas.ReportIn, db: Db):
    report = _get_report(db, report_id)
    for k, v in payload.model_dump().items():
        setattr(report, k, v)
    db.commit()
    db.refresh(report)
    return report


@router.delete("/reports/{report_id}", status_code=204)
def delete_report(report_id: int, db: Db):
    report = _get_report(db, report_id)
    db.delete(report)
    db.commit()


# ----------------------------------------------------------------- findings

@router.post("/reports/{report_id}/findings", response_model=schemas.FindingOut, status_code=201)
def add_finding(report_id: int, payload: schemas.FindingIn, db: Db):
    report = _get_report(db, report_id)
    finding = Finding(report=report, **payload.model_dump())
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


@router.put("/findings/{finding_id}", response_model=schemas.FindingOut)
def update_finding(finding_id: int, payload: schemas.FindingIn, db: Db):
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    for k, v in payload.model_dump().items():
        setattr(finding, k, v)
    db.commit()
    db.refresh(finding)
    return finding


@router.delete("/findings/{finding_id}", status_code=204)
def delete_finding(finding_id: int, db: Db):
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    db.delete(finding)
    db.commit()


# ------------------------------------------------------------------- import

class ImportResult(BaseModel):
    findings: list[schemas.FindingOut]
    context: dict


@router.post("/reports/{report_id}/import", response_model=ImportResult)
def import_findings(report_id: int, payload: schemas.ImportRequest, db: Db):
    """Parse findings from user-supplied text and attach them to the report.

    ``source_type`` can be explicit (yaml, nuclei, bb_workflow, burp) or
    ``auto`` to let the parser guess.
    """
    report = _get_report(db, report_id)
    try:
        findings, context = parse_findings(
            payload.content, payload.source_type, payload.source_label
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    rows = []
    findings = list(findings)
    if payload.dedupe:
        keys = existing_keys(report.findings)
        findings, _skipped = dedupe_raw(findings, keys)
    for rf in findings:
        row = Finding(
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
            status=rf.status,
        )
        db.add(row)
        rows.append(row)
    db.commit()
    return {"findings": rows, "context": context}


# ------------------------------------------------------------------ export

_TEMPLATE_TYPES = {"pentest", "va"}


@router.get("/reports/{report_id}/export")
def export_report(
    report_id: int,
    db: Db,
    format: str = Query("html", pattern="^(html|pdf|docx|md)$"),
):
    """Export a report in the requested format."""
    report = _get_report(db, report_id)
    findings = list(report.findings)
    filename = f"report_{report_id}.{format}"
    out = Path(f"/tmp/reportforge/{filename}")

    if format == "html":
        exporter.export_html(report, findings, out)
    elif format == "pdf":
        exporter.export_pdf(report, findings, out)
    elif format == "docx":
        exporter.export_docx(report, findings, out)
    elif format == "md":
        exporter._write(out, exporter.render_markdown(report, findings))

    return FileResponse(
        str(out),
        filename=f"{report.title.replace(' ', '_')}.{format}",
        media_type=_media_type(format),
    )


def _media_type(fmt: str) -> str:
    return {
        "html": "text/html; charset=utf-8",
        "pdf": "application/pdf",
        "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "md": "text/markdown; charset=utf-8",
    }[fmt]


# ------------------------------------------------------------ smart context

@router.get("/reports/{report_id}/smart-context")
def report_smart_context(report_id: int, db: Db):
    report = _get_report(db, report_id)
    return SmartContext().build_and_persist(report, list(report.findings), db)