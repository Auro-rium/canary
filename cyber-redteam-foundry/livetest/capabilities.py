"""Detect which lead-wiring pieces this checkout has (file-based; imports nothing).

Wiring-dependent assertions SKIP with a clear reason when a piece is absent; any
other missing effect is a FAIL. Once the wiring branch merges, detection flips
automatically and the assertions run.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

PKG = Path(__file__).resolve().parents[1] / "src" / "cyberredteam"


def _read(rel: str) -> str:
    try:
        return (PKG / rel).read_text(encoding="utf-8")
    except OSError:
        return ""


@dataclass(frozen=True)
class Capabilities:
    evaluation: bool  # WP5 monitors + evaluator + technique results run in the worker
    observability: bool  # init_observability called at worker start (W&B/Weave)
    gate_launcher: bool  # real CampaignLauncher behind `cyber-rt gate`
    judge_charged_to_ledger: bool  # judge spend charged to the campaign ledger

    def as_dict(self) -> dict[str, bool]:
        return {
            "evaluation_wiring": self.evaluation,
            "observability_wiring": self.observability,
            "gate_launcher": self.gate_launcher,
            "judge_charged_to_ledger": self.judge_charged_to_ledger,
        }


def detect() -> Capabilities:
    wiring = _read("jobs/evaluation_wiring.py")
    return Capabilities(
        evaluation=bool(wiring),
        observability="init_observability" in _read("jobs/worker.py"),
        gate_launcher="class QueueCampaignLauncher" in _read("gate/launcher.py"),
        # The harness always counts judge spend itself; this only records the code's state.
        judge_charged_to_ledger="charge_llm" in wiring,
    )
