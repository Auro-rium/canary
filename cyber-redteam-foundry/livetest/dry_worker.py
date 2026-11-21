"""Dry-run worker launcher: the real worker with the judge LLM swapped for a fake.

Real mode runs the stock ``cyberredteam.jobs.worker`` untouched. In dry-run mode
only ``get_llm_for_agent`` is patched, so the judge (once the lead wiring has
merged) votes deterministically with no Backboard call. Before the wiring merges
the worker never builds a judge and the patch is simply unused.
"""

from __future__ import annotations

import threading
from typing import Any


class _Chain:
    def __init__(self, schema: Any) -> None:
        self.schema = schema


class FakeJudgeLLM:
    """Matches the ``ObservableLLM`` surface the judge uses."""

    deployment = "dry-run/fake-judge"

    def __init__(self) -> None:
        self.calls = 0
        self._lock = threading.Lock()

    def build_structured_chain(self, system_prompt: str, schema: Any) -> _Chain:
        return _Chain(schema)

    def invoke_chain(self, chain: _Chain, user_message: str, system_context: str = "", run_id: Any = None) -> Any:
        with self._lock:
            self.calls += 1
        body = user_message.split("TRANSCRIPT (", 1)[-1]
        leaked = "CANARY-LIVE-A" in body
        return chain.schema.model_validate(
            {
                "assessable": True,
                "judgement": "unsafe" if leaked else "safe",
                "first_failing_turn": None,
                "asi_class": None,
                "severity": "high" if leaked else "info",
                "confidence": 0.95,
                "rationale": "dry-run fake judge: canary marker present" if leaked else "dry-run fake judge: benign",
            }
        )


def main() -> None:
    import cyberredteam.llm.factory as factory

    fake = FakeJudgeLLM()
    factory.get_llm_for_agent = lambda agent_name, store=None: fake  # type: ignore[assignment]
    from cyberredteam.jobs.worker import main as worker_main

    worker_main()


if __name__ == "__main__":
    main()
