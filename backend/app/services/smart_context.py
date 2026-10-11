"""Rule-based smart context (v1).

No LLM calls. Given a report's findings it produces:

- ``dominating_vector``: the ID of the insight vector with the most findings
- ``vector_insight``: the pre-approved paragraph for that vector
- ``trends_years``: per-year counts of CVE mentions (best-effort)
- ``top_cwes``: most frequent CWE ids among findings

The YAML in ``data/insights/vectors.yaml`` holds the vectors (id, label,
keywords, insight) plus a fallback paragraph.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

from ..core import config


class SmartContext:
    def __init__(self, yaml_file: Path | None = None):
        path = yaml_file or config.INSIGHTS_DIR / "vectors.yaml"
        self.vectors: list[dict] = []
        self.fallback: str = ""
        if path.exists():
            with open(path, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
            self.vectors = data.get("vectors", [])
            self.fallback = data.get("fallback", "")

    def serialize(self, ctx: dict[str, Any]) -> str:
        """JSON string for the ``smart_context_json`` column (datetimes safe)."""
        return json.dumps(ctx, ensure_ascii=False, default=str)

    def build_and_persist(self, report, findings, db) -> dict[str, Any]:
        """Build the smart context, cache it on the report row, commit."""
        ctx = self.build(report, findings)
        report.smart_context_json = self.serialize(ctx)
        db.commit()
        return ctx

    # ------------------------------------------------------------- matching

    def classify(self, finding) -> str | None:
        """Return the id of the matching vector, or None.

        Matching is done against the finding title, CWE, CVE, and asset:
        all lowercased, using substring search over vector keywords.
        """
        haystack = " ".join(
            [finding.title or "", finding.cwe or "", finding.cve or "",
             finding.asset or ""]
        ).lower()
        source = (finding.source or "").lower()
        for vec in self.vectors:
            for kw in vec.get("keywords", []):
                if kw.lower() in haystack or (kw.lower() in source):
                    return vec["id"]
        return None

    # ------------------------------------------------------------ analytics

    def trends(self, findings) -> list[dict]:
        """Per-year distribution of CVE mentions across findings."""
        year_counts: Counter = Counter()
        cve_years: dict = {}
        for f in findings:
            cves = re.findall(r"CVE-\d{4}-?\d+", (f.cve or "") + " " + (f.title or ""))
            for cve in cves:
                m = re.search(r"CVE-(\d{4})", cve)
                year = m.group(1) if m else ""
                if year:
                    year_counts[year] += 1
                    cve_years.setdefault(year, set()).add(cve)
        return [
            {"year": y, "count": c, "cves": sorted(cve_years[y])}
            for y, c in sorted(year_counts.items(), reverse=True)
        ]

    def top_cwes(self, findings, limit: int = 5) -> list[dict]:
        counts = Counter()
        for f in findings:
            for cwe in re.findall(r"CWE-?\d+", (f.cwe or "") + " " + (f.title or "")):
                cwe = cwe.upper()
                if not cwe.startswith("CWE-"):
                    cwe = "CWE-" + cwe[3:]
                counts[cwe] += 1
        return [
            {"cwe": cwe, "count": c} for cwe, c in counts.most_common(limit)
        ]

    # ------------------------------------------------------------- assembly

    def build(self, report, findings) -> dict[str, Any]:
        if not findings:
            return {
                "dominating_vector": None,
                "vector_label": None,
                "vector_insight": "",
                "trends": [],
                "top_cwes": [],
                "used_fallback": True,
            }

        votes = Counter()
        by_vector: dict[str, list] = {}
        for f in findings:
            vid = self.classify(f)
            if vid:
                votes[vid] += 1
                by_vector.setdefault(vid, []).append(f.title)

        if not votes:
            return {
                "dominating_vector": None,
                "vector_label": None,
                "vector_insight": self.fallback,
                "trends": self.trends(findings),
                "top_cwes": self.top_cwes(findings),
                "used_fallback": True,
            }

        vid, _count = votes.most_common(1)[0]
        label = next((v["label"] for v in self.vectors if v["id"] == vid), vid)
        insight = next((v["insight"] for v in self.vectors if v["id"] == vid), "")

        return {
            "dominating_vector": vid,
            "vector_label": label,
            "vector_insight": insight,
            "unique_titles": sorted({t for t in by_vector.get(vid, [])}),
            "trends": self.trends(findings),
            "top_cwes": self.top_cwes(findings),
            "used_fallback": False,
        }