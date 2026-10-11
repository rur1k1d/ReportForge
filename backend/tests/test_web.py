"""Web UI tests: every page renders, forms work."""

import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # backend/

from app.core import config as cfg  # noqa: E402

cfg.DB_PATH = Path(tempfile.mkdtemp()) / "test_web.db"  # type: ignore[misc]

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.core.database import engine  # noqa: E402
from app.models import Report  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def test_index_page(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "ReportForge" in r.text


def test_new_report_form(client):
    r = client.get("/reports/new")
    assert r.status_code == 200
    assert "New report" in r.text
    assert "name=\"title\"" in r.text

    r = client.post("/reports/new", data={
        "title": "Pentest - Test Client",
        "template_type": "pentest",
        "client": "Test Client",
        "scope": "https://test.example.com/",
        "version": "v0.1",
    }, follow_redirects=False)
    assert r.status_code == 303
    assert "/reports/" in r.headers["location"]


def test_edit_page_and_import(client):
    rid = client.post("/reports/new", data={"title": "R2", "client": "C"},
                      follow_redirects=False).headers["location"].rstrip("/").rsplit("/", 1)[-1]

    r = client.get(f"/reports/{rid}")
    assert r.status_code == 200
    assert "Smart Context" in r.text

    # import findings via the web form (auto-detect YAML)
    r = client.post(f"/reports/{rid}/import", data={
        "source_type": "auto",
        "content": "- title: Reflected XSS\n  severity: medium\n  asset: /q\n"
                   "- title: SQLi\n  severity: high\n  cwe: CWE-89\n",
    })
    assert r.status_code == 200
    assert "Imported 2 finding(s)" in r.text
    assert "Reflected XSS" in r.text


def test_smart_context_web(client):
    rid = client.post("/reports/new", data={"title": "R3", "client": "C"},
                      follow_redirects=False).headers["location"].rstrip("/").rsplit("/", 1)[-1]
    client.post(f"/reports/{rid}/import", data={
        "source_type": "auto",
        "content": "- title: Reflected XSS\n  severity: medium\n"
                   "- title: SQL injection\n  severity: high\n",
    })
    r = client.post(f"/reports/{rid}/smart-context")
    assert r.status_code == 200
    assert "webapp" in r.text.lower() or "Web application" in r.text
    # smart context is persisted on the report row
    with Session(engine) as s:
        row = s.get(Report, int(rid))
        assert row.smart_context_json
        assert "webapp" in row.smart_context_json


def test_export_web(client):
    rid = client.post("/reports/new", data={"title": "R4", "client": "C"},
                      follow_redirects=False).headers["location"].rstrip("/").rsplit("/", 1)[-1]
    for fmt, magic in [("html", b"<html"), ("pdf", b"%PDF"), ("docx", b"PK")]:
        r = client.get(f"/reports/{rid}/export?fmt={fmt}")
        assert r.status_code == 200, fmt
        assert magic in r.content[:300], f"{fmt} magic bytes missing"


def test_add_edit_delete_finding_web(client):
    rid = client.post("/reports/new", data={"title": "R5", "client": "C"},
                      follow_redirects=False).headers["location"].rstrip("/").rsplit("/", 1)[-1]

    # add one manually
    r = client.post(f"/reports/{rid}/findings/add", data={
        "title": "Manual issue", "severity": "high", "asset": "/x",
        "cwe": "CWE-119", "description": "d", "impact": "i",
        "recommendation": "fix", "evidence": "e",
    }, follow_redirects=False)
    assert r.status_code == 303

    page = client.get(f"/reports/{rid}").text
    assert "Manual issue" in page
    assert "CWE-119" in page

    # find its id from the page and edit it
    fid = -1
    import re as _re
    m = _re.search(r"/findings/(\d+)/update", page)
    assert m, "update route missing from page"
    fid = int(m.group(1))

    r = client.post(f"/findings/{fid}/update", data={
        "title": "Renamed issue", "severity": "low", "asset": "/y",
        "cwe": "", "description": "", "impact": "", "recommendation": "", "evidence": "",
    }, follow_redirects=False)
    assert r.status_code == 303
    page = client.get(f"/reports/{rid}").text
    assert "Renamed issue" in page
    assert "Manual issue" not in page

    # delete it
    r = client.post(f"/findings/{fid}/delete", follow_redirects=False)
    assert r.status_code == 303
    page = client.get(f"/reports/{rid}").text
    assert "Renamed issue" not in page


def test_import_dedupe(client):
    rid = client.post("/reports/new", data={"title": "R6", "client": "C"},
                      follow_redirects=False).headers["location"].rstrip("/").rsplit("/", 1)[-1]

    payload = "- title: Dup\n  severity: medium\n  asset: /a\n"
    r = client.post(f"/reports/{rid}/import", data={"source_type": "auto", "content": payload})
    assert "Imported 1 finding(s)" in r.text

    # same import again WITH dedupe on: nothing added, both skipped
    r = client.post(f"/reports/{rid}/import", data={
        "source_type": "auto", "content": payload, "dedupe": "true",
    })
    assert "Nothing imported" in r.text

    # a new finding + the existing one, dedupe on: only new lands
    mixed = payload + "- title: Fresh\n  severity: low\n  asset: /b\n"
    r = client.post(f"/reports/{rid}/import", data={
        "source_type": "auto", "content": mixed, "dedupe": "true",
    })
    assert "Imported 1 finding(s)" in r.text
    assert "duplicate(s) skipped" in r.text

    page = client.get(f"/reports/{rid}").text
    assert page.count(">Dup</b>") == 1  # still the original row
    assert "Fresh" in page