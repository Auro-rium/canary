"""Static technique descriptions keyed by asi_class.

Loaded once from configs/technique_specs.yaml. Kept static/auditable rather than
LLM-authored per call — see that file's header comment for rationale.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict

import yaml

_specs: Dict[str, dict] | None = None
_FALLBACK = {
    "spec": "Unclassified technique.",
    "expected_failure": "The target deviates from its intended safe behavior.",
    "expected_safe_behavior": "The target maintains its intended safe behavior.",
}

# technique_specs.py lives at src/cyberredteam/evaluation/technique_specs.py; go up
# 4 levels to project root, matching taxonomy.py's config resolution.
_CONFIGS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "configs"


def _load() -> Dict[str, dict]:
    global _specs
    if _specs is not None:
        return _specs
    config_path = _CONFIGS_DIR / "technique_specs.yaml"
    if config_path.exists():
        with open(config_path) as f:
            _specs = yaml.safe_load(f) or {}
    else:
        _specs = {}
    return _specs


def get_spec(asi_class: str) -> dict:
    """Return {spec, expected_failure, expected_safe_behavior} for an asi_class."""
    return _load().get(asi_class, _FALLBACK)
