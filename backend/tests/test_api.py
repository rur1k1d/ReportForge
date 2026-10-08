"""API tests via FastAPI TestClient.

Uses a temp DB (swap config.DB_PATH before importing the app) and exercises
the full flow: create report -> import findings -> export html/pdf.
"""

import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # backend/

from app.core import config as cfg  # noqa: E402

cfg.DB_PATH = Path(tempfile.mkdtemp()) / "test_api.db"  # type: ignore[misc]

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_report_crud(client):
    r = client.post("/api/reports", json={
        "title": "Pentest ACME",
        "template_type": "pentest",
        "client": "ACME",
        "scope": "https://acme.example.com/",
    })
    assert r.status_code == 201
    rid = r.json()["id"]

    r = client.get(f"/api/reports/{rid}")
    assert r.json()["title"] == "Pentest ACME"

    r = client.get("/api/reports")
    assert len(r.json()) == 1

    r = client.delete(f"/api/reports/{rid}")
    assert r.status_code == 204
    assert client.get(f"/api/reports/{rid}").status_code == 404


def test_import_yaml_findings(client):
    created = client.post("/api/reports", json={"title": "R", "client": "C"}).json()
    rid = created["id"]
    r = client.post(f"/api/reports/{rid}/import", json={
        "source_type": "yaml",
        "content": """
- title: Broken access control
  severity: high
  asset: /admin
  description: Direct object reference.
  recommendation: Check authorization server-side.
""",
    })
    assert r.status_code == 200
    findings = r.json()["findings"]
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"

    # second import with a duplicate title should create a new row
    r2 = client.post(f"/api/reports/{rid}/import", json={
        "source_type": "yaml",
        "content": "- title: Broken access control\n  severity: low\n",
    })
    assert len(r2.json()["findings"]) == 1


def test_export_html_via_api(client):
    rid = client.post("/api/reports", json={"title": "R", "client": "C"}).json()["id"]
    client.post(f"/api/reports/{rid}/import", json={
        "source_type": "yaml",
        "content": "- title: XSS\n  severity: medium\n  description: ex.\n",
    })
    r = client.get(f"/api/reports/{rid}/export?format=html")
    assert r.status_code == 200
    assert "XSS" in r.text