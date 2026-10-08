"""Tests for the rule-based smart context layer."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # backend/

from collections import namedtuple

from app.services.smart_context import SmartContext

F = namedtuple("Finding", "title cwe cve asset source")


def test_webapp_vector_classified():
    sc = SmartContext()
    f = F("Reflected XSS in search", "CWE-79", "", "https://app/", "")
    assert sc.classify(f) == "webapp"


def test_ad_vector_via_title():
    sc = SmartContext()
    f = F("Kerberoasting of service account", "", "", "dc01.corp", "")
    assert sc.classify(f) == "ad"


def test_fallback_when_unclassified():
    sc = SmartContext()
    f = F("Something unusual", "", "", "", "")
    assert sc.classify(f) is None


def test_build_dominating_vector():
    sc = SmartContext()
    fs = [F("XSS", "CWE-79", "", "", ""), F("SQLi", "CWE-89", "", "", ""),
          F("Kerberoast", "", "", "", "")]
    result = sc.build(None, fs)
    assert result["dominating_vector"] == "webapp"
    assert result["vector_label"] == "Web application"
    assert result["vector_insight"]  # non-empty
    assert not result["used_fallback"]


def test_build_empty_report():
    sc = SmartContext()
    result = sc.build(None, [])
    assert result["dominating_vector"] is None
    assert result["used_fallback"] is True


def test_trends_and_cwes():
    sc = SmartContext()
    fs = [
        F("CVE-2024-1234 in lib", "CWE-79", "CVE-2024-1234", "", ""),
        F("CVE-2023-999 old", "CWE-79", "CVE-2023-999", "", ""),
        F("no cve here", "", "", "", ""),
    ]
    result = sc.build(None, fs)
    assert result["trends"][0]["year"] == "2024"
    assert result["top_cwes"][0]["cwe"] == "CWE-79"
    assert result["top_cwes"][0]["count"] == 2