import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # backend/

from app.services.ingest import (  # noqa: E402
    dedupe_raw,
    existing_keys,
    from_burp_xml,
    from_nuclei_jsonl,
    from_yaml,
    parse_findings,
)


def test_yaml_minimal():
    findings, _ = parse_findings("""
- title: "Unauthenticated admin panel"
  severity: high
  asset: https://admin.example.com
  cwe: CWE-306
  description: "Admin panel without authentication."
  recommendation: "Require SSO login."
""", "yaml")
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].canonical_severity() == "high"
    assert findings[0].cwe == "CWE-306"


def test_yaml_cvss_passthrough():
    findings, _ = parse_findings("""
- title: RCE
  severity: critical
  cvss: 9.8
  asset: /api
""", "yaml")
    assert findings[0].cvss == "9.8"


def test_dedupe_helper():
    raw, _ = parse_findings("""
- title: Same
  severity: high
  asset: /a
- title: Same
  severity: high
  asset: /b
- title: Same
  severity: high
  asset: /a
""", "yaml")
    keys = existing_keys([])
    kept, skipped = dedupe_raw(raw, keys)
    assert len(kept) == 2  # /a + /b unique keys
    assert skipped == 1     # second /a filtered
    # keys updated in place
    assert ("same", "/a") in keys


def test_yaml_severity_alias():
    findings, _ = parse_findings("""
- title: x
  severity: Severe
""", "yaml")
    assert findings[0].canonical_severity() == "critical"


def test_nuclei_jsonl():
    line = json.dumps({
        "info": {"name": "XSS", "severity": "medium",
                 "description": "Reflected XSS",
                 "classification": {"cve-id": [], "cwe-id": ["CWE-79"],
                                    "cvss-metrics": ["CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"]}},
        "matched-at": "https://example.com/?q=1",
        "host": "example.com",
    })
    findings, _ = parse_findings(line + "\n", "nuclei")
    assert len(findings) == 1
    assert findings[0].title == "XSS"
    assert findings[0].cwe == "CWE-79"
    assert findings[0].canonical_severity() == "medium"
    assert findings[0].cvss.startswith("CVSS:3.1/AV:N")


def test_bb_workflow_report_real():
    path = Path(__file__).parents[1] / ".." / "null"
    # use sample data if present, else synthetic shape from bb_workflow
    payload = {
        "target": "example.com",
        "vulns": [
            {"info": {"name": "TLS issue", "severity": "medium",
                      "description": "Old TLS"},
             "matched-at": "https://example.com/", "host": "example.com"}
        ],
        "live": [{"url": "https://example.com/"}],
    }
    findings, ctx = parse_findings(json.dumps(payload), "bb_workflow")
    assert len(findings) == 1
    assert findings[0].source == "bb_workflow"
    assert ctx["target"] == "example.com"


def test_burp_xml():
    xml = """<?xml version="1.0"?>
<issues>
  <issue>
    <name>SQL Injection</name>
    <severity>High</severity>
    <host>https://app.example.com</host>
    <description>Parameter is injectable.</description>
    <remediation>Use parameterized queries.</remediation>
  </issue>
</issues>"""
    findings, _ = parse_findings(xml, "burp")
    assert len(findings) == 1
    assert findings[0].title == "SQL Injection"
    assert findings[0].canonical_severity() == "high"
    assert "parameterized" in findings[0].recommendation


def test_auto_detects_bbw_report():
    obj = {"target": "x", "vulns": [], "live": [], "subdomains": ["x"],
           "ports": [], "technologies": []}
    assert list(from_burp_xml("<issues/>")) == []
    findings, _ = parse_findings(json.dumps(obj), "auto")
    assert findings == []
    # and YAML auto path
    f2, _ = parse_findings("- title: hello\n  severity: low\n", "auto")
    assert f2[0].title == "hello"