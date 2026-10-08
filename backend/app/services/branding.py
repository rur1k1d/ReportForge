"""Branding loader (data/branding/<ref>.yaml) with defaults merged in.

A report references a branding profile by ``branding_ref``; profile "default"
always exists. Per-client YAML files override individual keys; the defaults
fill everything else.
"""

from __future__ import annotations

from typing import Any

import yaml

from ..models.finding import Severity

from ..core import config


def load_branding(ref: str = "default") -> dict[str, Any]:
    defaults = _read_yaml(config.BRANDING_DIR / "default.yaml", {})
    if not ref or ref == "default":
        return dict(**defaults)
    path = config.BRANDING_DIR / f"{ref}.yaml"
    if not path.exists():
        raise FileNotFoundError(
            f"branding profile not found: {ref} (checked {path})"
        )
    override = _read_yaml(path, {})
    merged = dict(defaults)
    merged.update(override)
    return merged


def available_branding() -> list[str]:
    names = ["default"]
    for p in sorted(config.BRANDING_DIR.glob("*.yaml")):
        if p.name != "default.yaml":
            names.append(p.stem)
    return names


def _read_yaml(path, fallback):
    if not path.exists():
        return fallback
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        return fallback
    return data


# severity colors (used by renderers, not branding)
SEVERITY_COLORS = {
    Severity.CRITICAL.value: "#7B0C0C",
    Severity.HIGH.value: "#B22222",
    Severity.MEDIUM.value: "#C78F00",
    Severity.LOW.value: "#2E6D2E",
    Severity.INFO.value: "#4A6E8E",
}