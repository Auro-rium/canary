"""Planner factories (WP4) for ``EngineDeps.planner_factory``.

``make_planner_factory`` does every check it can up front, so a
misconfigured campaign fails before its first turn instead of producing one
``error`` conversation per spec:

* ``"scripted"``: loads and validates every pack (schema, length cap, deny
  categories); with an explicit ``pack`` name it also checks that pack exists.
* ``"llm"``: reads ``prompts/planner.md`` (fail closed: PlannerPromptMissing),
  requires a scope classifier (ScopeClassifierMissing) and builds the
  ``planner`` role client once.

The returned callable builds one planner per conversation. A technique
mismatch (explicit pack for another technique) raises when that
conversation starts, which the engine records as ``error``.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Literal

from cyberredteam.engine.types import ConversationSpec, TurnPlanner
from cyberredteam.llm.observable import ObservableLLM
from cyberredteam.planners.errors import PlannerConfigError, ScopeClassifierMissing
from cyberredteam.planners.guards import DenyCategoryChecker, GuardRails, ScopeClassifier, default_deny_checker
from cyberredteam.planners.llm_planner import LLMPlanner, PlannerPrompt, load_planner_prompt
from cyberredteam.planners.packs import PackLoader
from cyberredteam.planners.scripted import ScriptedPlanner, validate_pack_messages
from cyberredteam.settings import get_settings

PlannerKind = Literal["scripted", "llm"]


def make_planner_factory(
    kind: PlannerKind,
    *,
    # scripted
    pack_loader: PackLoader | None = None,
    packs_dir: Path | str | None = None,
    pack: str | None = None,
    # llm
    llm: ObservableLLM | None = None,
    system_prompt: str | None = None,
    prompt_path: Path | str | None = None,
    # both
    scope_classifier: ScopeClassifier | None = None,
    deny_checker: DenyCategoryChecker | None = None,
    max_message_chars: int | None = None,
) -> Callable[[ConversationSpec], TurnPlanner]:
    """Return ``spec -> TurnPlanner`` for ``EngineDeps.planner_factory``.

    Scripted: ``pack`` pins one pack for every conversation (its technique
    must match); otherwise each conversation gets the packs for its
    technique, ``trial_index % n`` by name order. ``scope_classifier`` is
    optional here. LLM: ``scope_classifier`` is required.
    """
    settings = get_settings()
    cap = max_message_chars or settings.planner_max_message_chars
    deny = deny_checker or default_deny_checker()

    if kind == "scripted":
        loader = pack_loader or PackLoader(packs_dir or settings.planner_packs_dir)
        guards = GuardRails(max_message_chars=cap, deny_checker=deny, scope_classifier=scope_classifier)
        for p in loader.packs():
            validate_pack_messages(p, guards)
        pinned = loader.get(pack) if pack is not None else None

        def scripted_factory(spec: ConversationSpec) -> TurnPlanner:
            chosen = pinned if pinned is not None else loader.select(spec.technique, spec.trial_index)
            return ScriptedPlanner(chosen, spec.technique, guards)

        return scripted_factory

    if kind == "llm":
        prompt = (
            PlannerPrompt.from_text(system_prompt)
            if system_prompt is not None
            else load_planner_prompt(prompt_path)
        )
        if scope_classifier is None:
            raise ScopeClassifierMissing(
                "the LLM planner needs a technique-scope classifier and refuses to run without one"
            )
        if llm is None:
            from cyberredteam.llm.factory import get_llm_for_agent

            llm = get_llm_for_agent("planner")
        shared_llm = llm

        def llm_factory(spec: ConversationSpec) -> TurnPlanner:
            return LLMPlanner(
                spec.technique,
                scope_classifier=scope_classifier,
                llm=shared_llm,
                prompt=prompt,
                max_message_chars=cap,
                deny_checker=deny,
            )

        return llm_factory

    raise PlannerConfigError(f"unknown planner kind {kind!r} (expected 'scripted' or 'llm')")


__all__ = ["PlannerKind", "make_planner_factory"]
