"""Report ORM model."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..core.database import Base


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    template_type: Mapped[str] = mapped_column(String(40), nullable=False)  # pentest | va | ...
    client: Mapped[str] = mapped_column(String(120), nullable=False)
    scope: Mapped[str] = mapped_column(Text, default="")
    methodology: Mapped[str] = mapped_column(Text, default="")
    summary: Mapped[str] = mapped_column(Text, default="")  # exec summary (draft, editable)
    status: Mapped[str] = mapped_column(String(20), default="draft")  # draft | ready | final
    version: Mapped[str] = mapped_column(String(20), default="v0.1")
    branding_ref: Mapped[str] = mapped_column(String(120), default="default")
    smart_context_json: Mapped[str] = mapped_column(Text, default="")  # serialized insights
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now(), nullable=False
    )

    findings: Mapped[list["Finding"]] = relationship(  # noqa: F821
        "Finding", back_populates="report", cascade="all, delete-orphan"
    )