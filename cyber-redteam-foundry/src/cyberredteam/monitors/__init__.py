"""WP5 per-turn monitors implementing ``engine.types.TurnMonitor``.

Wire-up (lead, after merge)::

    deps = EngineDeps(..., monitors=build_monitors(), canary_values=..., forbidden_tools=...)

``build_monitors`` **replaces** ``BuiltinSafetyMonitor``: :class:`CanaryMonitor`
and :class:`ForbiddenToolMonitor` emit the same hit names with a superset of
its rules, so stacking both would double-count on ``Turn.monitor_hits``.
"""

from __future__ import annotations

from cyberredteam.engine.types import TurnMonitor
from cyberredteam.monitors.base import HitInfo, classify_hit, max_severity, result_from_hits
from cyberredteam.monitors.canary import CanaryMonitor, find_canary_leaks
from cyberredteam.monitors.config import TargetSafetyConfig, load_target_safety_config
from cyberredteam.monitors.pii import (
    PIIAnalyzer,
    PIIEntity,
    PIIMonitor,
    PIIUnavailable,
    PresidioAnalyzer,
)
from cyberredteam.monitors.secrets import SecretPatternMonitor
from cyberredteam.monitors.tools import ForbiddenToolMonitor


def build_monitors(pii_analyzer: PIIAnalyzer | None = None) -> list[TurnMonitor]:
    """The WP5 monitor set (critical ones first)."""
    return [
        CanaryMonitor(),
        ForbiddenToolMonitor(),
        SecretPatternMonitor(),
        PIIMonitor(pii_analyzer),
    ]


__all__ = [
    "CanaryMonitor",
    "ForbiddenToolMonitor",
    "HitInfo",
    "PIIAnalyzer",
    "PIIEntity",
    "PIIMonitor",
    "PIIUnavailable",
    "PresidioAnalyzer",
    "SecretPatternMonitor",
    "TargetSafetyConfig",
    "build_monitors",
    "classify_hit",
    "find_canary_leaks",
    "load_target_safety_config",
    "max_severity",
    "result_from_hits",
]
