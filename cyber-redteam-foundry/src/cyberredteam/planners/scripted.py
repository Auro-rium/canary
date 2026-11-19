"""ScriptedPlanner (WP4): deterministic replay of an operator-supplied pack.

The planner keeps no cursor. Each call re-derives the script position and
the branch taken purely from ``state.turns``, so a resumed conversation (the
engine builds a fresh planner on resume) continues exactly where it left off,
and two runs over the same target behaviour produce identical transcripts.
"""

from __future__ import annotations

from cyberredteam.engine.types import ConversationState, PlannedTurn
from cyberredteam.observability.hooks import trace_op
from cyberredteam.planners.errors import PackValidationError, TechniqueMismatch
from cyberredteam.planners.guards import GuardRails
from cyberredteam.planners.packs import Pack, ScriptTurn

PLANNER_KIND = "scripted"


def validate_pack_messages(pack: Pack, guards: GuardRails) -> None:
    """Load-time check of every message in a pack against the length cap and
    the deny categories (not the scope classifier, which runs per turn).
    Raises :class:`PackValidationError`."""
    for i, message in enumerate(pack.all_messages()):
        if len(message) > guards.max_message_chars:
            raise PackValidationError(
                f"pack {pack.name!r}: message {i} is {len(message)} chars, cap is {guards.max_message_chars}"
            )
        category = guards.deny_checker.check(message)
        if category is not None:
            raise PackValidationError(f"pack {pack.name!r}: message {i} matches deny category {category}")


class ScriptedPlanner:
    """Replays ``pack`` for one conversation of ``technique``."""

    def __init__(self, pack: Pack, technique: str, guards: GuardRails | None = None) -> None:
        if pack.technique != technique:
            raise TechniqueMismatch(
                f"pack {pack.name!r} is for technique {pack.technique!r}, "
                f"conversation technique is {technique!r}"
            )
        self.pack = pack
        self.technique = technique
        self.guards = guards or GuardRails()
        validate_pack_messages(pack, self.guards)

    def _script_position(self, state: ConversationState) -> tuple[list[ScriptTurn], int]:
        """Replay the transcript: which script is active and how far into it."""
        active: list[ScriptTurn] = list(self.pack.turns)
        pos = 0
        branched = False
        for turn in state.turns:
            pos += 1
            if branched:
                continue
            for key, branch in self.pack.branches.items():
                if key in turn.monitor_hits:
                    active, pos, branched = list(branch.turns), 0, True
                    break
        return active, pos

    def _end_condition_met(self, state: ConversationState) -> bool:
        if not state.turns:
            return False
        last = state.turns[-1]
        end = self.pack.end
        if any(h in last.monitor_hits for h in end.on_monitor_hits):
            return True
        response = last.response_text.lower()
        return any(s.lower() in response for s in end.on_response_contains)

    @trace_op("planner.scripted.next_turn")
    async def next_turn(self, state: ConversationState) -> PlannedTurn | None:
        if state.technique != self.technique:
            raise TechniqueMismatch(
                f"pack {self.pack.name!r} is for technique {self.technique!r}, "
                f"state technique is {state.technique!r}"
            )
        if self._end_condition_met(state):
            return None
        active, pos = self._script_position(state)
        if pos >= len(active):
            return None
        message = active[pos].message
        self.guards.check(
            message,
            planner=PLANNER_KIND,
            technique=self.technique,
            conversation_id=state.conversation_id,
            pack=self.pack.name,
            pack_version=self.pack.version,
        )
        return PlannedTurn(
            message=message,
            intent_note=f"pack={self.pack.name}@v{self.pack.version} step={pos}",
        )


__all__ = ["PLANNER_KIND", "ScriptedPlanner", "validate_pack_messages"]
