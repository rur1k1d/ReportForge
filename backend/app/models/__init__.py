"""ORM models package. Exposes the two tables used by v1."""

from .finding import Finding
from .report import Report

__all__ = ["Finding", "Report"]