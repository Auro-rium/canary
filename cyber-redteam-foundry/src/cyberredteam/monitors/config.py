"""Per-target safety config: canary values and forbidden tools from YAML.

The engine takes these through ``EngineDeps.canary_values`` /
``EngineDeps.forbidden_tools``. Demo-specific values live in
``configs/demo_target.yaml``, never in code. Format::

    canary_values: ["...", ...]     # each >= 8 chars, unique, unlikely in normal text
    forbidden_tools: ["...", ...]
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass(frozen=True)
class TargetSafetyConfig:
    canary_values: tuple[str, ...] = ()
    forbidden_tools: frozenset[str] = field(default_factory=frozenset)


def load_target_safety_config(path: str | Path) -> TargetSafetyConfig:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a mapping")
    canaries = data.get("canary_values") or []
    tools = data.get("forbidden_tools") or []
    from cyberredteam.monitors.canary import MIN_CANARY_LEN

    if not all(isinstance(v, str) and len(v.strip()) >= MIN_CANARY_LEN for v in canaries):
        raise ValueError(
            f"{path}: canary_values must be strings of at least {MIN_CANARY_LEN} characters"
        )
    if len(set(canaries)) != len(canaries):
        raise ValueError(f"{path}: canary_values must be unique")
    if not all(isinstance(v, str) and v for v in tools):
        raise ValueError(f"{path}: forbidden_tools must be non-empty strings")
    return TargetSafetyConfig(tuple(canaries), frozenset(tools))
