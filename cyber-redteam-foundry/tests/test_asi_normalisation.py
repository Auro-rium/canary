"""WP0: ASI codes are canonical (ASI01) and the backend taxonomy is the source of truth."""

import re
from pathlib import Path

import pytest

from cyberredteam.api import _STRATEGY_TO_ASI, _TECHNIQUE_TO_STRATEGY, _build_finding
from cyberredteam.contracts import ASI_CODE_PATTERN
from cyberredteam.evaluation.taxonomy import lookup
from cyberredteam.schemas import StrategyType
from cyberredteam.storage.models import AttackRecord

REPO = Path(__file__).resolve().parents[2]
TECHNIQUES_TS = REPO / "canary" / "src" / "lib" / "techniques.ts"


def _ui_techniques() -> dict[str, str]:
    text = TECHNIQUES_TS.read_text()
    pairs = re.findall(r"id:\s*'([^']+)',\s*asiCode:\s*'([^']+)'", text)
    assert pairs, "could not parse techniques.ts"
    return dict(pairs)


def test_ui_techniques_match_backend_taxonomy():
    ui = _ui_techniques()
    assert set(ui) == set(_TECHNIQUE_TO_STRATEGY)
    for slug, code in ui.items():
        expected = lookup(_TECHNIQUE_TO_STRATEGY[slug].value, "*")[0]
        assert code == expected, f"{slug}: UI says {code}, taxonomy says {expected}"


def test_strategy_to_asi_is_canonical_and_taxonomy_derived():
    assert set(_STRATEGY_TO_ASI) == {s.value for s in StrategyType}
    for strategy, code in _STRATEGY_TO_ASI.items():
        assert re.match(ASI_CODE_PATTERN, code)
        assert code == lookup(strategy, "*")[0]


def _attack(asi_class=None, strategy="tool_misuse"):
    indicators = {"asi_class": asi_class} if asi_class is not None else {}
    return AttackRecord(
        id=1, run_id="r1", target_id="t", attempt_number=1, strategy_type=strategy,
        prompt="p", response="r", success=True, severity="high", score=0.8,
        score_threshold=0.5, finding_id="f1", indicators=indicators,
    )


@pytest.mark.parametrize(
    "asi_class,strategy,expected",
    [
        ("ASI02", "tool_misuse", "ASI02"),
        ("ASI-04", "tool_misuse", "ASI04"),  # legacy DB value normalised
        (None, "tool_misuse", "ASI02"),  # fallback from taxonomy
        (None, "memory_poisoning", "ASI05"),
        ("garbage", "sensitive_data_exposure", "ASI04"),  # invalid value never surfaces
        (None, "unknown_strategy", "ASI01"),  # taxonomy catch-all
    ],
)
def test_finding_payload_asi_code_is_canonical(asi_class, strategy, expected):
    assert _build_finding(_attack(asi_class, strategy), "r1")["asi_code"] == expected
