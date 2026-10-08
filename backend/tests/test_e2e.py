"""End-to-end smoke test through the API using a real YAML library file.

Flow: create report -> import findings from data/findings_library ->
       smart context -> export pdf/html/docx -> assert files are valid.
"""

import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # backend/

from app.core import config as cfg  # noqa: E402

cfg.DB_PATH = Path(tempfile.mkdtemp()) / "test_e2e.db"  # type: ignore[misc]

from fastapi.testclient import TestClient  # noqa: E402
from app.main import app  # noqa: E402


FINDINGS_LIB = (
    Path(__file__).resolve().parents[1] / ".." / "data" / "findings_library" / "webapp_findings.yaml"
).read_text(encoding="utf-8")


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def test_full_flow(client):
    # 1. create report
    r = client.post("/api/reports", json={
        "title": "Pentest Report - ACME Corp",
        "template_type": "pentest",
        "client": "ACME Corp",
        "scope": "https://acme.example.com/",
    })
    assert r.status_code == 201
    rid = r.json()["id"]

    # 2. import 6 findings from the library
    r = client.post(f"/api/reports/{rid}/import", json={
        "source_type": "yaml",
        "source_label": "library:webapp_findings.yaml",
        "content": FINDINGS_LIB,
    })
    assert r.status_code == 200
    fs = r.json()["findings"]
    assert len(fs) == 6
    assert {f["severity"] for f in fs} == {"high", "medium", "low"}

    # 3. smart context = rule-based vector
    r = client.get(f"/api/reports/{rid}/smart-context")
    assert r.status_code == 200
    sc = r.json()
    assert sc["dominating_vector"] == "webapp"
    assert "Web application" in sc["vector_label"]
    assert sc["top_cwes"][0]["cwe"] == "CWE-79"

    # 4. export each format; each must produce a non-trivial file
    for fmt, magic in [("html", b"<html"), ("pdf", b"%PDF"), ("docx", b"PK")]:
        r = client.get(f"/api/reports/{rid}/export?format={fmt}")
        assert r.status_code == 200
        assert magic in r.content[:200], f"{fmt} missing magic bytes"