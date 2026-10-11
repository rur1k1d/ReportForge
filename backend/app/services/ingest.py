"""Finding ingestion and normalization.

Every external source (bb_workflow report.json, nuclei JSON lines, Burp XML,
manual YAML) is normalized to the canonical Finding fields used by the ORM
model and by the report renderers.

Severity is always canonicalized through ``enums.SEVERITY_ALIASES``; anything
unrecognized falls back to "medium" and is reported so nobody silently loses
a finding's severity.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Iterable

import yaml

from ..models.enums import SEVERITY_ALIASES


@dataclass
class RawFinding:
    """Source-agnostic finding, ready to be stored as a Finding row."""

    title: str
    severity: str
    cvss: str = ""
    description: str = ""
    impact: str = ""
    recommendation: str = ""
    evidence: str = ""
    cwe: str = ""
    cve: str = ""
    mitre: str = ""
    asset: str = ""
    source: str = "manual"
    status: str = "open"
    extra: dict = field(default_factory=dict)

    def canonical_severity(self) -> str:
        sev = (self.severity or "medium").strip().lower()
        return normalize_severity(sev)

    def dedupe_key(self) -> tuple[str, str]:
        """Key for de-duplication: (title, asset).""" 
        return (self.title.strip().lower(), self.asset.strip().lower())


def normalize_severity(value: str) -> str:
    """Map any external severity word to a canonical one.

    Returns the canonical value or ``"medium"`` if unknown (never fails).
    """
    return SEVERITY_ALIASES.get(value.strip().lower(), "medium")


def existing_keys(findings) -> set[tuple[str, str]]:
    """(title, asset) pairs already stored on a report (for de-duplication)."""
    return {
        (f.title.strip().lower(), (f.asset or "").strip().lower())
        for f in findings
    }


def dedupe_raw(
    raw: list["RawFinding"], keys: set[tuple[str, str]]
) -> tuple[list["RawFinding"], int]:
    """Drop findings whose (title, asset) key is already in ``keys``.

    Returns (kept, skipped). ``keys`` is updated in place with the kept
    findings so later batches in the same import also see them.
    """
    kept: list[RawFinding] = []
    skipped = 0
    for rf in raw:
        key = (rf.title.strip().lower(), (rf.asset or "").strip().lower())
        if key in keys:
            skipped += 1
            continue
        keys.add(key)
        kept.append(rf)
    return kept, skipped


# ----------------------------------------------------------- decode: YAML ---


def _clean_yaml(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return "\n".join(str(v) for v in value)
    return str(value)


def from_yaml(text: str, source: str = "manual") -> Iterable[RawFinding]:
    """Parse manual findings YAML.

    YAML shape:
      - title: "Unauthenticated admin panel"
        severity: high
        asset: https://app.example.com/admin
        cwe: CWE-306
        cvss: 8.1
        description: "..."
        impact: "..."
        recommendation: "..."
        evidence: "..."
    """
    data = yaml.safe_load(text)
    if not data:
        return []
    if isinstance(data, dict):
        data = [data]
    for item in data:
        if not isinstance(item, dict):
            continue
        f = RawFinding(
            title=str(item.get("title", "Untitled finding")).strip(),
            severity=str(item.get("severity", "medium")).strip(),
            cvss=str(item.get("cvss", "") or "").strip(),
            description=_clean_yaml(item.get("description")),
            impact=_clean_yaml(item.get("impact")),
            recommendation=_clean_yaml(item.get("recommendation")),
            evidence=_clean_yaml(item.get("evidence")),
            cwe=str(item.get("cwe", "")).strip(),
            cve=str(item.get("cve", "")).strip(),
            mitre=str(item.get("mitre", "")).strip(),
            asset=str(item.get("asset", "")).strip(),
            source=source,
        )
        if f.title and f.title != "Untitled finding":
            yield f


# ---------------------------------------------------- decode: nuclei JSONL ---


def from_nuclei_jsonl(text: str) -> Iterable[RawFinding]:
    """Parse nuclei -jsonl output (one JSON object per line)."""
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue  # non-JSON noise
        info = obj.get("info") or {}
        if not info.get("name"):
            continue
        classification = info.get("classification") or {}
        cvss_metrics = classification.get("cvss-metrics", [])
        if isinstance(cvss_metrics, list):
            cvss = ", ".join(str(x) for x in cvss_metrics)
        else:
            cvss = str(cvss_metrics or "")
        yield RawFinding(
            title=str(info.get("name", "nuclei finding")).strip(),
            severity=str(info.get("severity", "medium")).strip(),
            cvss=cvss,
            description=str(info.get("description", "")).strip(),
            recommendation=str(
                info.get("remediation", info.get("recommendation", ""))
            ).strip(),
            evidence=str(obj.get("matched-at", "")).strip(),
            cve=", ".join(classification.get("cve-id", []))
            if isinstance(classification.get("cve-id"), list)
            else str(classification.get("cve-id", "")),
            cwe=", ".join(classification.get("cwe-id", []))
            if isinstance(classification.get("cwe-id"), list)
            else str(classification.get("cwe-id", "")),
            asset=str(obj.get("host", obj.get("matched-at", ""))).strip(),
            source="nuclei",
        )


# ------------------------------------------------------ decode: bb_workflow ---


def from_bb_workflow(obj: dict) -> tuple[Iterable[RawFinding], dict]:
    """Parse a bb_workflow ``report.json``.

    Returns (findings, context) where context carries the target/scope facts
    (live endpoints, subdomains, tech) that a pentest report's Scope section
    uses. The report-level fields are picked up by the caller, not here.
    """
    target = obj.get("target", "")
    findings = []
    for v in obj.get("vulns", []):
        info = v.get("info") or {}
        if not info.get("name"):
            continue
        classification = info.get("classification") or {}
        cvss_metrics = classification.get("cvss-metrics", [])
        if isinstance(cvss_metrics, list):
            cvss = ", ".join(str(x) for x in cvss_metrics)
        else:
            cvss = str(cvss_metrics or "")
        findings.append(
            RawFinding(
                title=str(info.get("name", "nuclei finding")).strip(),
                severity=str(info.get("severity", "medium")).strip(),
                cvss=cvss,
                description=str(info.get("description", "")).strip(),
                recommendation=str(
                    info.get("remediation", info.get("recommendation", ""))
                ).strip(),
                evidence=str(v.get("matched-at", "")).strip(),
                asset=str(v.get("host", target or "")).strip(),
                source="bb_workflow",
            )
        )
    context = {
        "target": target,
        "live": [r.get("url") for r in obj.get("live", [])],
        "subdomains": obj.get("subdomains", []),
        "ports": obj.get("ports", []),
        "technologies": obj.get("technologies", []),
    }
    return findings, context


def from_json_document(obj: dict) -> Iterable[RawFinding]:
    """Dispatch: if it looks like a bb_workflow report, use that parser."""
    if "vulns" in obj and "live" in obj and "target" in obj:
        findings, _ctx = from_bb_workflow(obj)
        return findings
    return []


# --------------------------------------------------------- decode: Burp XML


_NS = "{http://www.portswigger.net/burp/extender}"


def _local_tag(tag: str) -> str:
    """'name' out of {namespace}name, namespaced or not."""
    return tag.rsplit("}", 1)[-1]


def _findtext(element: ET.Element, name: str) -> str:
    """findtext that tolerates a missing/extra namespace on the tag."""
    for el in element.iter():
        if _local_tag(el.tag) == name:
            return (el.text or "").strip()
    return ""


def from_burp_xml(text: str) -> Iterable[RawFinding]:
    """Parse a Burp Suite XML export (<issues> with <issue> entries)."""
    root = ET.fromstring(text)
    # handle both namespaced and plain <issue> elements
    for issue in root.iter():
        if _local_tag(issue.tag) != "issue":
            continue
        title = _findtext(issue, "name")
        if not title:
            continue
        severity = _findtext(issue, "severity")
        desc = _findtext(issue, "description")
        # Burp description contains <tags>...<!--...--> and <b> markup
        desc = re.sub(r"<[^>]+>", "", desc).strip()
        remediation = _findtext(issue, "remediation")
        remediation = re.sub(r"<[^>]+>", "", remediation).strip()
        evidence = _findtext(issue, "remediation_manual")
        host = _findtext(issue, "host")
        yield RawFinding(
            title=title,
            severity=severity,
            description=desc,
            recommendation=remediation,
            evidence=evidence,
            asset=host,
            source="burp",
        )


# ------------------------------------------------------------- dispatcher ---


def parse_findings(
    content: str,
    source_type: str = "auto",
    source_label: str = "",
) -> tuple[list[RawFinding], dict]:
    """Parse findings from raw text, guessing the format if source_type=auto.

    Returns (findings, context); context is only populated for bb_workflow.
    """
    content = content.strip()
    context: dict = {}
    st = source_type.lower()

    if st == "auto":
        if content.startswith("{"):  # JSON: nuclei line or bb_workflow report
            try:
                obj = json.loads(content)
            except json.JSONDecodeError:
                obj = None
            if obj is not None and "vulns" in obj and "target" in obj:
                st = "bb_workflow"
            elif obj is not None:
                st = "nuclei"
        elif content.startswith("<"):  # XML: Burp
            st = "burp"
        elif content.startswith("-") or content.startswith("  ") or "title:" in content:
            st = "yaml"
        else:
            st = "yaml"

    if st == "yaml":
        return list(from_yaml(content, source=source_label or "manual")), {}
    if st == "nuclei":
        return list(from_nuclei_jsonl(content)), {}
    if st == "bb_workflow":
        obj = json.loads(content)
        findings, context = from_bb_workflow(obj)
        return list(findings), context
    if st == "burp":
        return list(from_burp_xml(content)), {}
    raise ValueError(f"unknown source type: {source_type}")