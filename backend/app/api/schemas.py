"""Pydantic schemas for the API layer."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class FindingIn(BaseModel):
    """Payload for creating/updating a single finding."""
    title: str = Field(..., min_length=1, max_length=200)
    severity: str = "medium"
    cvss: str = ""
    description: str = ""
    impact: str = ""
    recommendation: str = ""
    evidence: str = ""
    cwe: str = ""
    cve: str = ""
    mitre: str = ""
    asset: str = ""
    status: str = "open"
    source: str = "manual"


class FindingOut(FindingIn):
    model_config = ConfigDict(from_attributes=True)

    id: int
    severity: str
    created_at: datetime


class ReportIn(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    template_type: str = Field("pentest", pattern="^(pentest|va)$")
    client: str = "Client"
    scope: str = ""
    methodology: str = ""
    summary: str = ""
    status: str = "draft"
    version: str = "v0.2"
    branding_ref: str = "default"


class ReportOut(ReportIn):
    model_config = ConfigDict(from_attributes=True)

    id: int
    findings: list[FindingOut] = []
    created_at: datetime
    updated_at: datetime


class ImportRequest(BaseModel):
    source_type: str = Field("auto", pattern="^(auto|yaml|nuclei|bb_workflow|burp)$")
    content: str = Field(..., min_length=1)
    source_label: str = ""
    dedupe: bool = False