import pytest

from cyberredteam.release_gate import (
    create_project,
    create_release,
    accept_baseline,
    finalise_release,
    upsert_ci_project,
    validate_public_http_endpoint,
)
from cyberredteam.storage.artifact_store import SQLiteStore
from cyberredteam.storage.models import FindingRecord, RunRecord


def _complete_run(session, run_id: str) -> None:
    session.add(RunRecord(run_id=run_id, target_id="https://agent.example.test/chat", status="completed"))


def test_release_comparison_distinguishes_known_and_new_findings(tmp_path):
    store = SQLiteStore(tmp_path / "release-gate.db")
    try:
        with store.SessionLocal() as session:
            project = create_project(
                session,
                {
                    "name": "Customer Support",
                    "endpoint": "https://agent.example.test/chat",
                    "strategies": ["prompt_injection", "sensitive_data_exposure"],
                    "gate": {"block_on": ["critical", "high"], "max_new_findings": 0},
                },
            )
            baseline = create_release(session, project, "a820fc", "preview")
            baseline.run_id = "run-baseline"
            _complete_run(session, baseline.run_id)
            session.add(
                FindingRecord(
                    finding_id="known-pii",
                    target_id=project.endpoint,
                    strategy="sensitive_data_exposure",
                    severity="high",
                    first_seen_run=baseline.run_id,
                    last_seen_run=baseline.run_id,
                )
            )
            session.commit()
            finalise_release(session, baseline.release_id)
            accept_baseline(session, baseline.release_id, "test-admin")

            current = create_release(session, project, "def456", "preview")
            current.run_id = "run-current"
            _complete_run(session, current.run_id)
            known = session.get(FindingRecord, "known-pii")
            known.last_seen_run = current.run_id
            session.add(
                FindingRecord(
                    finding_id="new-auth-boundary",
                    target_id=project.endpoint,
                    strategy="authorization_boundary",
                    severity="critical",
                    first_seen_run=current.run_id,
                    last_seen_run=current.run_id,
                )
            )
            session.commit()
            result = finalise_release(session, current.release_id)

            assert result.decision == "block"
            assert result.comparison["known_finding_ids"] == ["known-pii"]
            assert result.comparison["new_finding_ids"] == ["new-auth-boundary"]
            assert result.summary["coverage"] == 100
    finally:
        store.close()


def test_target_registration_rejects_loopback_addresses():
    with pytest.raises(ValueError, match="private or reserved"):
        validate_public_http_endpoint("http://127.0.0.1:9000/chat")


def test_ci_uses_last_passing_main_release_not_a_pr_as_baseline(tmp_path):
    store = SQLiteStore(tmp_path / "ci-release-gate.db")
    try:
        with store.SessionLocal() as session:
            project = upsert_ci_project(
                session,
                {
                    "repository": "auro-rium/demo-agent",
                    "name": "auro-rium/demo-agent",
                    "endpoint": "https://agent.example.test/chat",
                    "strategies": ["sensitive_data_exposure", "authorization_boundary"],
                    "gate": {"block_on": ["critical", "high"], "max_new_findings": 0},
                },
            )
            safe = create_release(session, project, "safe-main", "preview", git_ref="main", event_name="push")
            safe.run_id = "safe-run"
            _complete_run(session, safe.run_id)
            session.add(FindingRecord(
                finding_id="known-low", target_id=project.endpoint, strategy="sensitive_data_exposure",
                severity="low", first_seen_run=safe.run_id, last_seen_run=safe.run_id,
            ))
            session.commit()
            safe = finalise_release(session, safe.release_id, default_branch="main")
            assert safe.decision == "pass"
            assert safe.is_baseline == 1
            accept_baseline(session, safe.release_id, "test-admin")

            pr = create_release(session, project, "pr-head", "preview", git_ref="feature/docs", event_name="pull_request")
            pr.run_id = "pr-run"
            _complete_run(session, pr.run_id)
            known = session.get(FindingRecord, "known-low")
            known.last_seen_run = pr.run_id
            session.add(FindingRecord(
                finding_id="new-critical", target_id=project.endpoint, strategy="authorization_boundary",
                severity="critical", first_seen_run=pr.run_id, last_seen_run=pr.run_id,
            ))
            session.commit()
            pr = finalise_release(session, pr.release_id, default_branch="main")
            assert pr.decision == "block"
            assert pr.baseline_release_id == safe.release_id
            assert pr.is_baseline == 0
            assert pr.comparison["new_finding_ids"] == ["new-critical"]
    finally:
        store.close()
