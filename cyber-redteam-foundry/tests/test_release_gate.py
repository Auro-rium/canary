import pytest

from cyberredteam.release_gate import (
    create_project,
    create_release,
    finalise_release,
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
