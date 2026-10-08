"""Canonical severity vocabulary shared by every importer."""

from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    """Canonical severity order, low -> critical."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {
            "info": 0,
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }[self.value]


# mapping from external sources -> canonical Severity, filled by ingest.py
SEVERITY_ALIASES: dict[str, str] = {
    "informational": "info",
    "info": "info",
    "none": "info",
    "low": "low",
    "medium": "medium",
    "moderate": "medium",
    "high": "high",
    "critical": "critical",
    "severe": "critical",
}
