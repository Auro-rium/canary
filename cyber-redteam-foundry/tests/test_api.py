"""Tests for the FastAPI web server endpoints."""

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from cyberredteam.api import app, settings, CampaignRunRequest, run_orchestrator_thread
from cyberredteam.schemas import StrategyType
from cyberredteam.storage.artifact_store import SQLiteStore
from cyberredteam.storage.models import RunRecord, AttackRecord
from pathlib import Path
from datetime import datetime

client = TestClient(app)


@pytest.fixture
def mock_db(tmp_path):
    """Fixture to set up a temporary test database and clean it after test."""
    original_db_path = settings.db_path
    temp_db = tmp_path / "test_api.db"
    settings.db_path = temp_db

    # Initialize tables
    store = SQLiteStore(temp_db)
    
    # Insert some dummy records
    with store.SessionLocal() as session:
        # Run
        run = RunRecord(
            run_id="testrun123",
            target_id="Finance Agent",
            start_time=datetime.utcnow(),
            status="completed",
            total_attacks=1,
            successful_attacks=1,
            success_rate=1.0,
        )
        session.add(run)

        # Attack
        attack = AttackRecord(
            run_id="testrun123",
            attempt_number=1,
            strategy_type="prompt_injection",
            prompt="Hello attack",
            response="Breached!",
            success=1,
            severity="high",
            score=0.9,
            indicators={"test": True},
        )
        session.add(attack)
        session.commit()
    
    yield store
    
    store.close()
    settings.db_path = original_db_path


def test_get_status():
    """Test the status endpoint."""
    response = client.get("/api/status")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"


def test_get_incidents(mock_db):
    """Test fetching incidents list from the database."""
    response = client.get("/api/incidents")
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 1
    assert data[0]["agent"] == "Finance Agent"
    assert data[0]["type"] == "Prompt Injection"
    assert data[0]["status"] == "Critical"
    assert data[0]["riskScore"] == 90


def test_get_run_details(mock_db):
    """Test retrieving details of a run."""
    # Test valid run
    response = client.get("/api/runs/testrun123")
    assert response.status_code == 200
    data = response.json()
    assert data["run_id"] == "testrun123"
    assert data["target_id"] == "Finance Agent"
    assert data["status"] == "completed"
    assert len(data["attacks"]) == 1

    # Test invalid run
    response_invalid = client.get("/api/runs/nonexistent")
    assert response_invalid.status_code == 404


def test_get_analysis_report(mock_db):
    """Test retrieving the structured analysis report for a run."""
    response = client.get("/api/runs/testrun123/analysis-report")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == "testrun123"
    assert data["agent"] == "Finance Agent"
    assert data["severity"] == "High"
    assert data["confidence"] == 90
    assert len(data["trace"]) >= 2


def test_create_run_endpoint(mock_db):
    """Test creating/triggering a run."""
    # target_id must be in ALLOWED_TARGETS — the endpoint now enforces the
    # allowlist (previously it silently accepted anything when unset).
    response = client.post(
        "/api/runs",
        json={"target_id": "http://host.docker.internal:9000/chat", "strategy": "Prompt Injection", "intensity": "Low"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "run_id" in data
    assert data["status"] == "running"
    assert data["target_id"] == "http://host.docker.internal:9000/chat"


def test_create_run_concurrency_cap_rejects_when_full(mock_db, monkeypatch):
    """Test that POST /api/runs returns 429 when concurrent cap is reached."""
    from cyberredteam.api import active_runs

    # Monkeypatch max_concurrent_runs to 1 for this test
    monkeypatch.setattr(settings, "max_concurrent_runs", 1)

    # Pre-populate active_runs with a "running" entry to hit the cap
    active_runs["existing-run"] = "running"

    try:
        # Attempt to create a new run when cap is reached
        response = client.post(
            "/api/runs",
            json={"target_id": "http://host.docker.internal:9000/chat", "strategy": "Prompt Injection", "intensity": "Low"},
        )
        assert response.status_code == 429
        data = response.json()
        assert "concurrent" in data["detail"].lower()
    finally:
        # Clean up: remove the test-inserted key
        if "existing-run" in active_runs:
            del active_runs["existing-run"]


def test_create_run_concurrency_cap_ignores_non_running(mock_db, monkeypatch):
    """Test that completed/failed runs don't count toward the concurrency cap."""
    from cyberredteam.api import active_runs

    # Monkeypatch max_concurrent_runs to 1 for this test
    monkeypatch.setattr(settings, "max_concurrent_runs", 1)

    # Pre-populate active_runs with several completed/failed entries (more than cap)
    active_runs["completed-run-1"] = "completed"
    active_runs["completed-run-2"] = "completed"
    active_runs["failed-run-1"] = "failed"

    try:
        # Attempt to create a new run — should succeed because no "running" entries exist
        response = client.post(
            "/api/runs",
            json={"target_id": "http://host.docker.internal:9000/chat", "strategy": "Prompt Injection", "intensity": "Low"},
        )
        # May fail for other reasons (e.g., orchestrator setup), but NOT 429
        assert response.status_code != 429
    finally:
        # Clean up: remove the test-inserted keys
        for key in ["completed-run-1", "completed-run-2", "failed-run-1"]:
            if key in active_runs:
                del active_runs[key]


def test_campaign_run_request_defaults_and_custom_target_config():
    """Generic HTTP target config fields default to empty/None and pass through when set."""
    req = CampaignRunRequest(campaign_id="c1", target_url="http://example.com/chat", techniques=[])
    assert req.headers == {}
    assert req.request_template is None
    assert req.response_path is None

    req = CampaignRunRequest(
        campaign_id="c1",
        target_url="http://example.com/v1/chat/completions",
        techniques=["prompt_injection"],
        headers={"X-API-Key": "secret"},
        request_template='{"messages": [{"role": "user", "content": "{{PROMPT}}"}]}',
        response_path="choices.0.message.content",
    )
    assert req.headers == {"X-API-Key": "secret"}
    assert req.request_template == '{"messages": [{"role": "user", "content": "{{PROMPT}}"}]}'
    assert req.response_path == "choices.0.message.content"


def test_run_orchestrator_thread_passes_target_config_into_run_config():
    """run_orchestrator_thread must thread headers/request_template/response_path into RunConfig."""
    captured = {}

    class FakeOrchestrator:
        def __init__(self, config, **kwargs):
            captured["config"] = config

        def run(self):
            return {}

    with patch("cyberredteam.api.GraphOrchestrator", FakeOrchestrator):
        run_orchestrator_thread(
            run_id="run-target-cfg",
            target_id="http://example.com/v1/chat/completions",
            strategy_types=[StrategyType.PROMPT_INJECTION],
            max_iterations=1,
            max_attempts=1,
            target_headers={"X-API-Key": "secret"},
            target_request_template='{"messages": [{"role": "user", "content": "{{PROMPT}}"}]}',
            target_response_path="choices.0.message.content",
        )

    config = captured["config"]
    assert config.target_headers == {"X-API-Key": "secret"}
    assert config.target_request_template == '{"messages": [{"role": "user", "content": "{{PROMPT}}"}]}'
    assert config.target_response_path == "choices.0.message.content"


def test_ci_release_auto_registers_repository_from_checked_in_config(mock_db, monkeypatch):
    """The reusable Action must not require a dashboard project ID."""
    captured = {}

    def fake_start(project, **kwargs):
        captured["project"] = project
        captured.update(kwargs)
        return {"release_id": "ci-release", "status": "running"}

    monkeypatch.setattr("cyberredteam.api.validate_public_http_endpoint", lambda *args, **kwargs: None)
    monkeypatch.setattr("cyberredteam.api._start_release", fake_start)
    response = client.post(
        "/api/ci/releases",
        json={
            "repository": "Auro-rium/canary-demo-agent",
            "commit_sha": "deadbeef",
            "ref": "feature/document-access",
            "event_name": "pull_request",
            "default_branch": "main",
            "endpoint": "https://preview.example.test/chat",
            "request_template": '{"message":"{{PROMPT}}"}',
            "response_path": "response",
            "strategies": ["prompt_injection", "sensitive_data_exposure"],
            "gate": {"block_on": ["critical"], "max_new_findings": 0},
        },
    )
    assert response.status_code == 202
    assert response.json()["release_id"] == "ci-release"
    assert captured["project"].repository == "auro-rium/canary-demo-agent"
    assert captured["git_ref"] == "feature/document-access"
    assert captured["default_branch"] == "main"
