"""CI gate (WP10): differential comparison of two campaigns' technique results.

Regression suites: ScriptedPlanner packs (WP4) are the fixed, deterministic
regression suites the gate runs. LLMPlanner runs are exploratory and are not
gated.
"""

from cyberredteam.gate.differential import (
    GatePolicy,
    GateResult,
    GateStatus,
    TechniqueDiff,
    TechniqueOverride,
    TechniqueStatus,
    compare,
)

__all__ = [
    "GatePolicy",
    "GateResult",
    "GateStatus",
    "TechniqueDiff",
    "TechniqueOverride",
    "TechniqueStatus",
    "compare",
]
