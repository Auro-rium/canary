"""Gate orchestration: load results, compare, render, report metrics."""

from __future__ import annotations

import json
import os
import tempfile
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from cyberredteam.contracts import CampaignPolicy, TargetConfig, TechniqueResult
from cyberredteam.gate.differential import GatePolicy, GateResult, TechniqueStatus, compare
from cyberredteam.gate.launcher import CampaignLauncher, LaunchError
from cyberredteam.gate.report import to_json, to_markdown
from cyberredteam.storage.v2.repositories import CampaignRepo


class GateError(Exception):
    """Operational error; the CLI maps it to exit code 2."""


def load_policy(path: str | None) -> GatePolicy:
    if not path:
        return GatePolicy()
    try:
        return GatePolicy.model_validate(json.loads(Path(path).read_text()))
    except (OSError, ValueError) as exc:
        raise GateError(f"cannot load policy {path}: {exc}") from exc


def _results(
    repo: CampaignRepo, campaign_id: str, target_id: str | None, role: str
) -> list[TechniqueResult]:
    rec = repo.get(campaign_id)
    if rec is None:
        raise GateError(f"{role} campaign not found: {campaign_id}")
    if target_id and rec.target_id != target_id:
        raise GateError(f"{role} campaign {campaign_id} belongs to a different target")
    results = repo.technique_results(campaign_id)
    if not results:
        raise GateError(f"{role} campaign {campaign_id} has no technique results")
    return results


def run_gate(
    repo: CampaignRepo,
    *,
    target_id: str | None,
    suite: str,
    baseline_id: str,
    candidate_id: str | None,
    policy: GatePolicy,
    launcher: CampaignLauncher | None = None,
) -> tuple[GateResult, str, str]:
    """Returns (result, markdown, json). Raises GateError for operational failures."""
    if candidate_id is None:
        if launcher is None or target_id is None:
            raise GateError("no --candidate given and no campaign launcher is configured")
        try:
            candidate_id = launcher.launch(target_id, suite)
        except LaunchError as exc:
            raise GateError(str(exc)) from exc
    base = _results(repo, baseline_id, target_id, "baseline")
    cand = _results(repo, candidate_id, target_id, "candidate")
    result = compare(base, cand, policy)
    tgt = target_id or ""
    md = to_markdown(result, target=tgt, suite=suite, baseline=baseline_id, candidate=candidate_id)
    js = to_json(result, target=tgt, suite=suite, baseline=baseline_id, candidate=candidate_id)
    _log_metrics(candidate_id, result, suite)
    return result, md, js


def _log_metrics(candidate_id: str, result: GateResult, suite: str) -> None:
    """Soft observability hook (WP11 maps job_type="gate" to a W&B run); never raises."""
    try:
        from cyberredteam.observability.hooks import get_metrics

        get_metrics().campaign_finished(
            candidate_id,
            {
                "job_type": "gate",
                "suite": suite,
                "gate_status": result.status.value,
                "regressions": len(result.of(TechniqueStatus.REGRESSION)),
            },
        )
    except Exception:  # noqa: BLE001 - observability must not affect the gate
        pass


def write_step_summary(markdown: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(markdown)


# ── demo mode ────────────────────────────────────────────────────────────────

# (technique, trials, confirmed)
_BASELINE = [("prompt_injection", 20, 2), ("data_exfiltration", 20, 0), ("tool_abuse", 20, 5)]
_HEALTHY = [("prompt_injection", 20, 3), ("data_exfiltration", 20, 0), ("tool_abuse", 20, 4)]
_REGRESSED = [("prompt_injection", 20, 3), ("data_exfiltration", 20, 12), ("tool_abuse", 20, 4)]


@contextmanager
def demo_session(*, inject_regression: bool) -> Iterator[tuple[CampaignRepo, str, str, str]]:
    """Seed two synthetic campaigns into a throwaway SQLite DB; clean up on exit.

    Yields (repo, target_id, baseline_id, candidate_id). The temp directory is
    removed and CANARY_ENCRYPTION_KEY restored to its previous value afterwards.
    """
    from cyberredteam.storage.v2 import orm
    from cyberredteam.storage.v2.db import make_engine, make_session_factory
    from cyberredteam.storage.v2.encrypted import reset_key_cache
    from cyberredteam.storage.v2.repositories import SqlTargetStore

    prev_key = os.environ.get("CANARY_ENCRYPTION_KEY")
    engine = None
    try:
        with tempfile.TemporaryDirectory(prefix="canary-gate-") as tmp:
            if not prev_key:
                from cryptography.fernet import Fernet

                os.environ["CANARY_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
                reset_key_cache()
            engine = make_engine(f"sqlite:///{Path(tmp) / 'demo.db'}")
            orm.Base.metadata.create_all(engine)
            factory = make_session_factory(engine)
            target = TargetConfig(
                target_id=str(uuid.uuid4()),
                name="demo-fake-target",
                endpoint="http://127.0.0.1:9/chat",
                auth={"type": "none"},
                session_mode="stateless_history",
                environment="staging",
            )
            SqlTargetStore(factory).create(target)
            repo = CampaignRepo(factory)
            policy = CampaignPolicy(
                techniques=[t for t, _, _ in _BASELINE], trials_per_technique=20
            )
            cand_rows = _REGRESSED if inject_regression else _HEALTHY
            for cid, rows in (("demo-baseline", _BASELINE), ("demo-candidate", cand_rows)):
                repo.create(cid, target.target_id, policy, created_by="gate-demo")
                repo.save_technique_results(
                    cid, [TechniqueResult.from_counts(t, n, k) for t, n, k in rows]
                )
            yield repo, target.target_id, "demo-baseline", "demo-candidate"
    finally:
        if engine is not None:
            engine.dispose()
        if prev_key is None:
            os.environ.pop("CANARY_ENCRYPTION_KEY", None)
        else:
            os.environ["CANARY_ENCRYPTION_KEY"] = prev_key
        reset_key_cache()
