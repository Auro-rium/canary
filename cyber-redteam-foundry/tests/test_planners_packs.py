"""WP4 pack schema and PackLoader: validation, determinism, selection."""

from __future__ import annotations

from pathlib import Path

import pytest

from cyberredteam.planners import (
    PackLoader,
    PackNotFound,
    PackValidationError,
    parse_pack,
)
from cyberredteam.planners.packs import DEFAULT_PACKS_DIR


def _pack(**over):
    data = {
        "name": "p1",
        "version": 1,
        "technique": "smoke_greeting",
        "turns": [{"message": "hi"}],
    }
    data.update(over)
    return data


def _write(dir_: Path, name: str, text: str) -> Path:
    path = dir_ / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_valid_pack_with_branches_and_end():
    pack = parse_pack(
        _pack(
            branches={"marker_hit": {"turns": [{"message": "branch hello"}]}},
            end={"on_monitor_hits": ["x"], "on_response_contains": ["bye"]},
        )
    )
    assert pack.all_messages() == ["hi", "branch hello"]
    assert pack.end.on_response_contains == ["bye"]


@pytest.mark.parametrize(
    "over, needle",
    [
        ({"surprise": 1}, "surprise"),  # unknown top-level field
        ({"turns": [{"message": "hi", "extra": 1}]}, "extra"),  # unknown turn field
        ({"turns": []}, "turns"),
        ({"turns": [{"message": "   "}]}, "blank"),
        ({"version": 0}, "version"),
        ({"name": "has space"}, "name"),
        ({"technique": ""}, "technique"),
        ({"branches": {"hit": {"turns": []}}}, "branches"),
        ({"branches": {"hit": {"turns": [{"message": "x"}], "goto": 2}}}, "goto"),
        ({"end": {"on_monitor_hits": [""]}}, "blank"),
        ({"end": {"after": 3}}, "after"),
    ],
)
def test_pack_validation_errors(over, needle):
    with pytest.raises(PackValidationError) as err:
        parse_pack(_pack(**over), source="bad.yaml")
    assert "bad.yaml" in str(err.value) and needle in str(err.value)


def test_missing_required_fields():
    with pytest.raises(PackValidationError, match="technique"):
        parse_pack({"name": "p", "version": 1, "turns": [{"message": "hi"}]})


def test_non_mapping_and_bad_yaml(tmp_path):
    with pytest.raises(PackValidationError, match="mapping"):
        parse_pack(["not", "a", "mapping"])
    _write(tmp_path, "broken.yaml", "name: [unclosed\n")
    with pytest.raises(PackValidationError, match="invalid YAML"):
        PackLoader(tmp_path)


def test_loader_is_deterministic_and_rejects_duplicates(tmp_path):
    _write(tmp_path, "b/two.yaml", "name: two\nversion: 1\ntechnique: t\nturns:\n  - message: b\n")
    _write(tmp_path, "a/one.yml", "name: one\nversion: 1\ntechnique: t\nturns:\n  - message: a\n")
    _write(tmp_path, "notes.txt", "ignored")
    first, second = PackLoader(tmp_path), PackLoader(tmp_path)
    assert first.names == second.names == ["one", "two"]
    # Trial i gets pack i % n, by name order.
    assert [first.select("t", i).name for i in range(4)] == ["one", "two", "one", "two"]

    _write(tmp_path, "c/dupe.yaml", "name: one\nversion: 2\ntechnique: t\nturns:\n  - message: c\n")
    with pytest.raises(PackValidationError, match="duplicate pack name"):
        PackLoader(tmp_path)


def test_loader_not_found(tmp_path):
    with pytest.raises(PackNotFound):
        PackLoader(tmp_path / "missing")
    _write(tmp_path, "one.yaml", "name: one\nversion: 1\ntechnique: t\nturns:\n  - message: a\n")
    loader = PackLoader(tmp_path)
    with pytest.raises(PackNotFound, match="other"):
        loader.select("other")
    with pytest.raises(PackNotFound, match="nope"):
        loader.get("nope")


def test_shipped_smoke_packs_are_benign_and_valid():
    loader = PackLoader(DEFAULT_PACKS_DIR)
    assert loader.names == ["smoke-context-retention", "smoke-greeting"]
    assert {p.technique for p in loader.packs()} == {"smoke_greeting", "smoke_context_retention"}
    # Only smoke packs ship with the code; real packs come from the security owner.
    assert all(p.relative_to(DEFAULT_PACKS_DIR).parts[0] == "smoke"
               for p in DEFAULT_PACKS_DIR.rglob("*.y*ml"))
