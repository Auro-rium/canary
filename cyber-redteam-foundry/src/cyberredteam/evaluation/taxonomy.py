"""ASI/ATLAS taxonomy lookup.

Maps (strategy, component) pairs to ASI class and ATLAS technique IDs
using the static config in configs/asi_taxonomy.yaml.  The judge's
asi_class_suggested is informational only; this lookup is authoritative.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Tuple

import yaml

_taxonomy: list | None = None
_FALLBACK = ("ASI01", "AML.T0051.000")

# Absolute path so CWD at runtime doesn't affect config resolution.
# taxonomy.py lives at src/cyberredteam/evaluation/taxonomy.py; go up 4 levels to project root.
_CONFIGS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "configs"


def _load() -> list:
    global _taxonomy
    if _taxonomy is not None:
        return _taxonomy
    config_path = _CONFIGS_DIR / "asi_taxonomy.yaml"
    if config_path.exists():
        with open(config_path) as f:
            data = yaml.safe_load(f) or {}
        _taxonomy = data.get("mappings", [])
    else:
        _taxonomy = []
    return _taxonomy


def lookup(strategy: str, component: str) -> Tuple[str, str]:
    """Return (asi_class, atlas_technique) for a given strategy + component.

    Matching rules:
    - Exact strategy + exact component wins first.
    - Exact strategy + wildcard component wins second.
    - Wildcard strategy + wildcard component is the catch-all.
    """
    mappings = _load()
    strat = (strategy or "").lower()
    comp = (component or "").lower()

    exact_match = None
    wildcard_comp_match = None
    wildcard_both_match = None

    for m in mappings:
        ms = (m.get("strategy") or "").lower()
        mc = (m.get("component") or "").lower()
        if ms == strat and mc == comp:
            exact_match = m
            break
        if ms == strat and mc == "*" and wildcard_comp_match is None:
            wildcard_comp_match = m
        if ms == "*" and mc == "*" and wildcard_both_match is None:
            wildcard_both_match = m

    best = exact_match or wildcard_comp_match or wildcard_both_match
    if best:
        return best.get("asi_class", _FALLBACK[0]), best.get("atlas_technique", _FALLBACK[1])
    return _FALLBACK
