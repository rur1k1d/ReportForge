"""End-to-end render/export smoke test (no network, no UI).

Creates a Report row + Findings in a temp DB, renders Pentest HTML,
exports PDF + DOCX + HTML, and asserts basic invariants.
"""

import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # backend/

# swap DB to a temp file so tests never touch data/reportforge.db
from app.core import config as cfg  # noqa: E402

cfg.DB_PATH = Path(tempfile.mkdtemp()) / "test_export.db"  # type: ignore[misc]

from app.core.database import init_db  # noqa: E402
from app.models import Finding, Report  # noqa: E402
from app.services import exporter  # noqa: E402


@pytest.fixture(scope="module")
def report(db_session):
    r = Report(
        title="Pentest Report: ACME Corp",
        template_type="pentest",
        client="ACME Corp",
        scope="https://acme.example.com/ (web app)",
        version="v1.0",
    )
    fs = [
        Finding(
            report=r,
            title="Reflected XSS in search",
            severity="high",
            cwe="CWE-79",
            asset="https://acme.example.com/search",
            description="Search parameter echoed unsanitized.",
            impact="Session theft possible.",
            recommendation="HTML-encode output.",
            evidence='GET /search?q=<script>alert(1)</script> → reflected',
        ),
        Finding(
            report=r,
            title="Missing CSP header",
            severity="medium",
            asset="https://acme.example.com/",
            description="No Content-Security-Policy on main app.",
        ),
    ]
    db_session.add(r)
    db_session.add_all(fs)
    db_session.commit()
    yield r
    db_session.delete(r)
    db_session.commit()


@pytest.fixture(scope="module")
def db_session():
    init_db()
    from app.core.database import SessionLocal

    db = SessionLocal()
    yield db
    db.close()


def test_render_html(report, db_session):
    html = exporter.render_html(report, report.findings, "default")
    assert "ACME Corp" in html
    assert "Reflected XSS in search" in html
    assert "CWE-79" in html
    assert "Content-Security-Policy" in html


def test_export_html_file(report, db_session, tmp_path):
    out = exporter.export_html(report, report.findings, tmp_path / "report.html")
    assert out.exists()
    assert "Reflected XSS" in out.read_text(encoding="utf-8")


def test_export_pdf(report, db_session, tmp_path):
    out = exporter.export_pdf(report, report.findings, tmp_path / "report.pdf")
    assert out.exists()
    assert out.stat().st_size > 500  # valid PDF is never empty


def test_export_docx(report, db_session, tmp_path):
    out = exporter.export_docx(report, report.findings, tmp_path / "report.docx")
    assert out.exists()
    assert out.stat().st_size > 500