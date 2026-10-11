"""Application configuration and path layout.

Paths are resolved relative to the repository root (the folder that contains
``backend/`` and ``data/``), not relative to the current working directory.
This keeps the project runnable from anywhere.
"""

from __future__ import annotations

import os
from pathlib import Path

# backend/app/core/config.py -> repo root is three levels up
APP_DIR = Path(__file__).resolve().parent.parent.parent  # backend/
REPO_ROOT = APP_DIR.parent  # ReportForge_Project/

# Local-only by default. Set REPORTFORGE_ORIGINS to a comma-separated list of
# allowed origins (e.g. "http://localhost:3000,http://192.168.1.10:8000")
# when the API is used from a different origin.
CORS_ORIGINS = [
    o.strip()
    for o in os.environ.get("REPORTFORGE_ORIGINS", "http://127.0.0.1:8000").split(",")
    if o.strip()
]

# project-wide dirs (declared here so they can be overridden in tests)
DATA_DIR = REPO_ROOT / "data"
BRANDING_DIR = DATA_DIR / "branding"
INSIGHTS_DIR = DATA_DIR / "insights"
FINDINGS_LIBRARY_DIR = DATA_DIR / "findings_library"
SAMPLE_REPORTS_DIR = DATA_DIR / "sample_reports"
RENDER_TEMPLATES_DIR = APP_DIR / "app" / "templates" / "render"

# database file lives next to the repo so it survives cwd changes
DB_PATH = DATA_DIR / "reportforge.db"

# repository-level defaults
DEFAULT_USER = "Pentest-IT"
DEFAULT_COMPANY = "Pentest-IT"
DEFAULT_LANGUAGE = "pl"


def ensure_dirs() -> None:
    """Create every data directory that must exist before first run."""
    for d in (DATA_DIR, BRANDING_DIR, INSIGHTS_DIR, FINDINGS_LIBRARY_DIR,
              SAMPLE_REPORTS_DIR):
        d.mkdir(parents=True, exist_ok=True)


ensure_dirs()