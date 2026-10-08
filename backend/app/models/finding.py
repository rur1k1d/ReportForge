"""Finding ORM model."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..core.database import Base
from .enums import Severity


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    report_id: Mapped[int] = mapped_column(
        ForeignKey("reports.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), default=Severity.MEDIUM.value)
    cvss: Mapped[str] = mapped_column(String(10), default="")
    cwe: Mapped[str] = mapped_column(String(20), default="")
    cve: Mapped[str] = mapped_column(String(40), default="")
    mitre: Mapped[str] = mapped_column(String(40), default="")
    asset: Mapped[str] = mapped_column(String(200), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    impact: Mapped[str] = mapped_column(Text, default="")
    recommendation: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(20), default="open")  # open | fixed | accepted
    source: Mapped[str] = mapped_column(String(40), default="manual")  # manual|bb_workflow|nuclei|burp
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )

    report: Mapped["Report"] = relationship(  # noqa: F821
        "Report", back_populates="findings"
    )