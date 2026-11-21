"""Turn-script packs (WP4): schema and deterministic loader.

A pack is a YAML file with operator-supplied turns for one technique::

    name: greeting                # unique across the packs directory
    version: 1
    technique: smoke_greeting     # must equal the conversation's technique
    asi_class: ASI01              # optional OWASP ASI code the pack targets
    success_signal: canary_leak   # optional: what a successful attack looks like
    description: optional text
    turns:                        # sent in order
      - message: "Hello!"
    branches:                     # optional, keyed on a monitor hit name
      some_monitor_hit:
        turns:
          - message: "..."
    end:                          # optional early-end conditions
      on_monitor_hits: [hit_name]
      on_response_contains: ["goodbye"]

Branch semantics: after each turn, if no branch has been taken yet and that
turn's ``monitor_hits`` contain a branch key, the rest of the main script is
replaced by that branch's turns. Keys are tried in pack order, so the choice
is deterministic. Only one branch is ever taken.

End conditions are checked against the most recent turn; a match ends the
conversation normally (the planner returns ``None``).

Pack sets: ``packs/smoke/`` (benign CI/live-test packs, the default) and
``packs/attacks/`` (adversarial packs for owner-verified test agents only; see
its README). ``PackLoader(dir, pack_set=...)`` selects ``smoke``, ``attacks`` or
``all``. Branch keys are monitor hit names; only non-critical hits can fire a
branch, because a critical hit already stops the conversation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from cyberredteam.planners.errors import PackNotFound, PackValidationError

# packs/ sits at the project root: .../src/cyberredteam/planners/packs.py -> parents[3]
DEFAULT_PACKS_DIR = Path(__file__).resolve().parents[3] / "packs"


# A pack file larger than this is rejected before it is read or parsed (a runaway
# or hostile file must not exhaust worker memory at factory build).
MAX_PACK_FILE_BYTES = 256 * 1024


class _PackModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ScriptTurn(_PackModel):
    message: str = Field(min_length=1)

    @field_validator("message")
    @classmethod
    def _non_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("message must not be blank")
        return v


class Branch(_PackModel):
    turns: list[ScriptTurn] = Field(min_length=1)


class EndConditions(_PackModel):
    on_monitor_hits: list[str] = Field(default_factory=list)
    on_response_contains: list[str] = Field(default_factory=list)

    @field_validator("on_monitor_hits", "on_response_contains")
    @classmethod
    def _non_blank_items(cls, v: list[str]) -> list[str]:
        if any(not s.strip() for s in v):
            raise ValueError("entries must not be blank")
        return v


SuccessSignal = Literal[
    "canary_leak",
    "forbidden_tool_call",
    "system_prompt_disclosure",
    "cross_user_data",
    "instruction_override",
    "policy_violation",
]
PackSet = Literal["smoke", "attacks", "all"]
PACK_SETS: tuple[str, ...] = ("smoke", "attacks", "all")


class Pack(_PackModel):
    name: str = Field(min_length=1, pattern=r"^[A-Za-z0-9_.-]+$")
    version: int = Field(ge=1)
    technique: str = Field(min_length=1)
    description: str = ""
    asi_class: str | None = Field(default=None, pattern=r"^ASI(0[1-9]|10)$")
    success_signal: SuccessSignal | None = None
    turns: list[ScriptTurn] = Field(min_length=1)
    branches: dict[str, Branch] = Field(default_factory=dict)
    end: EndConditions = Field(default_factory=EndConditions)

    @model_validator(mode="after")
    def _branch_keys(self) -> "Pack":
        if any(not k.strip() for k in self.branches):
            raise ValueError("branch keys (monitor hit names) must not be blank")
        if not self.technique.strip():
            raise ValueError("technique must not be blank")
        return self

    def all_messages(self) -> list[str]:
        out = [t.message for t in self.turns]
        for branch in self.branches.values():
            out.extend(t.message for t in branch.turns)
        return out


def parse_pack(data: object, source: str = "<pack>") -> Pack:
    """Validate one decoded pack document. Raises :class:`PackValidationError`."""
    if not isinstance(data, dict):
        raise PackValidationError(f"{source}: a pack must be a YAML mapping")
    try:
        return Pack.model_validate(data)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in e['loc']) or '<root>'}: {e['msg']}" for e in exc.errors()
        )
        raise PackValidationError(f"{source}: {problems}") from None


def load_pack_file(path: Path) -> Pack:
    try:
        with path.open("rb") as fh:
            raw = fh.read(MAX_PACK_FILE_BYTES + 1)  # bounded read; never the whole file
    except OSError as exc:
        raise PackValidationError(f"{path.name}: cannot read ({type(exc).__name__})") from None
    if len(raw) > MAX_PACK_FILE_BYTES:
        raise PackValidationError(f"{path.name}: pack file exceeds {MAX_PACK_FILE_BYTES} bytes")
    try:
        data = yaml.safe_load(raw.decode("utf-8"))
    except UnicodeDecodeError:
        raise PackValidationError(f"{path.name}: not valid UTF-8") from None
    except yaml.YAMLError as exc:
        raise PackValidationError(f"{path.name}: invalid YAML ({type(exc).__name__})") from None
    return parse_pack(data, source=path.name)


class PackLoader:
    """Loads every ``*.yaml`` / ``*.yml`` under ``directory`` (recursively,
    sorted by relative path) once, eagerly, so a bad pack fails before a
    campaign starts. Pack names must be unique.

    Selection by technique is deterministic: the packs for a technique are
    ordered by name and conversation trial ``i`` gets pack ``i % n``.
    """

    def __init__(self, directory: Path | str | None = None, pack_set: str | None = None) -> None:
        """``pack_set`` limits loading to ``<directory>/smoke`` or ``<directory>/attacks``
        (``all`` and ``None`` load everything under ``directory``)."""
        self.directory = Path(directory) if directory is not None else DEFAULT_PACKS_DIR
        if not self.directory.is_dir():
            raise PackNotFound(f"packs directory not found: {self.directory}")
        if pack_set is not None and pack_set not in PACK_SETS:
            raise PackNotFound(f"unknown pack set {pack_set!r} (expected one of {', '.join(PACK_SETS)})")
        root = self.directory / pack_set if pack_set in ("smoke", "attacks") else self.directory
        if not root.is_dir():
            raise PackNotFound(f"pack set directory not found: {root}")
        paths = sorted(
            (p for p in root.rglob("*") if p.suffix in {".yaml", ".yml"} and p.is_file()),
            key=lambda p: p.relative_to(self.directory).as_posix(),
        )
        packs: dict[str, Pack] = {}
        for path in paths:
            pack = load_pack_file(path)
            if pack.name in packs:
                raise PackValidationError(f"{path.name}: duplicate pack name {pack.name!r}")
            packs[pack.name] = pack
        self._packs = packs

    @property
    def names(self) -> list[str]:
        return sorted(self._packs)

    def packs(self) -> list[Pack]:
        return [self._packs[n] for n in self.names]

    def get(self, name: str) -> Pack:
        try:
            return self._packs[name]
        except KeyError:
            raise PackNotFound(f"no pack named {name!r} in {self.directory}") from None

    def for_technique(self, technique: str) -> list[Pack]:
        return [p for p in self.packs() if p.technique == technique]

    def select(self, technique: str, trial_index: int = 0) -> Pack:
        candidates = self.for_technique(technique)
        if not candidates:
            raise PackNotFound(f"no pack for technique {technique!r} in {self.directory}")
        return candidates[trial_index % len(candidates)]


__all__ = [
    "DEFAULT_PACKS_DIR",
    "MAX_PACK_FILE_BYTES",
    "PACK_SETS",
    "Branch",
    "EndConditions",
    "Pack",
    "PackLoader",
    "PackSet",
    "ScriptTurn",
    "SuccessSignal",
    "load_pack_file",
    "parse_pack",
]
