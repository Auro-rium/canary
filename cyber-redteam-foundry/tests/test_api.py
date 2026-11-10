"""Tests for the FastAPI web server endpoints."""

import uuid
from datetime import datetime
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from cyberredteam.api import (
    CampaignRunRequest,
    app,
    get_target_store,
    run_orchestrator_thread,
    settings,
)
from cyberredteam.contracts import TargetConfig
from cyberredteam.schemas import StrategyType
from cyberredteam.security.crypto import generate_key
from cyberredteam.security.targets import InMemoryTargetStore
from cyberredteam.storage.artifact_store import SQLiteStore
from cyberredteam.storage.models import AttackRecord, FindingRecord, LLMCallRecord, RunRecord

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
        session.add(LLMCallRecord(
            run_id="testrun123",
            agent_name="attacker",
            deployment="nvidia/nemotron-test",
            latency=1.25,
            input_hash="input",
            output_hash="output",
            prompt_tokens=100,
            completion_tokens=25,
        ))
        session.add(FindingRecord(
            finding_id="finding123",
            target_id="Finance Agent",
            strategy="prompt_injection",
            asi_class="ASI01",
            severity="high",
            status="open",
        ))
        session.commit()

    yield store

    store.close()
    settings.db_path = original_db_path


@pytest.fixture
def target_store(monkeypatch):
    """A fresh registered-target store injected into the API."""
    monkeypatch.setenv("CANARY_ENCRYPTION_KEY", generate_key())
    store = InMemoryTargetStore()
    app.dependency_overrides[get_target_store] = lambda: store
    yield store
    app.dependency_overrides.pop(get_target_store, None)


@pytest.fixture
def verified_target(target_store, monkeypatch):
    """A registered + ownership-verified target; the orchestrator thread is stubbed
    so no run ever reaches the network."""
    cfg = TargetConfig(
        target_id=str(uuid.uuid4()),
        name="Finance Agent",
        endpoint="https://agent.example.com/chat",
        session_mode="stateless_history",
        environment="staging",
    )
    target_store.create(cfg)
    target_store.set_verified(cfg.target_id, "http_wellknown")
    monkeypatch.setattr("cyberredteam.api.run_orchestrator_thread", lambda *a, **k: None)
    return cfg


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
    assert data["llm_stats"]["total_tokens"] == 125

    # Test invalid run
    response_invalid = client.get("/api/runs/nonexistent")
    assert response_invalid.status_code == 404


def test_dashboard_overview_and_campaign_history(mock_db):
    """Dashboard summary/list endpoints expose persisted facts without raw evidence."""
    overview = client.get("/api/dashboard/overview")
    assert overview.status_code == 200
    assert overview.json()["campaigns"]["total"] == 1
    assert overview.json()["open_findings"]["by_severity"]["high"] == 1
    assert overview.json()["llm_stats"]["total_tokens"] == 125

    runs = client.get("/api/runs?page=1&page_size=25&target_id=Finance%20Agent")
    assert runs.status_code == 200
    payload = runs.json()
    assert payload["total"] == 1
    assert payload["items"][0]["run_id"] == "testrun123"
    assert payload["items"][0]["llm_stats"]["total_tokens"] == 125
    assert "attacks" not in payload["items"][0]


def test_target_portfolio(mock_db):
    response = client.get("/api/targets")
    assert response.status_code == 200
    target = response.json()["items"][0]
    assert target["target_id"] == "Finance Agent"
    assert target["campaign_count"] == 1
    assert target["open_findings"] == 1


def test_target_detail_routes_accept_http_url_target_ids(mock_db):
    """Coverage/trend routes must support the slash-containing HTTP IDs used by the UI."""
    with mock_db.SessionLocal() as session:
        run = session.scalar(select(RunRecord).where(RunRecord.run_id == "testrun123"))
        run.target_id = "http://agent.example/chat"
        attack = session.scalar(select(AttackRecord).where(AttackRecord.run_id == "testrun123"))
        attack.target_id = "http://agent.example/chat"
        finding = session.scalar(select(FindingRecord).where(FindingRecord.finding_id == "finding123"))
        finding.target_id = "http://agent.example/chat"
        session.commit()

    coverage = client.get("/api/targets/http://agent.example/chat/coverage")
    assert coverage.status_code == 200
    assert coverage.json()["target_id"] == "http://agent.example/chat"
    trends = client.get("/api/targets/http://agent.example/chat/trends")
    assert trends.status_code == 200


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


def test_create_run_endpoint(mock_db, verified_target):
    """Test creating/triggering a run against a registered, verified target."""
    response = client.post(
        "/api/runs",
        json={"target_id": verified_target.target_id, "strategy": "Prompt Injection", "intensity": "Low"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "run_id" in data
    assert data["status"] == "running"
    assert data["target_id"] == verified_target.target_id
    assert data["endpoint"] == "https://agent.example.com/chat"


def test_create_run_refuses_unregistered_target(mock_db, target_store):
    """No fail-open path: an unregistered target (even a URL) is refused."""
    response = client.post(
        "/api/runs",
        json={"target_id": "http://host.docker.internal:9000/chat", "strategy": "Prompt Injection", "intensity": "Low"},
    )
    assert response.status_code == 403


def test_create_run_concurrency_cap_rejects_when_full(mock_db, monkeypatch, verified_target):
    """Test that POST /api/runs returns 429 when concurrent cap is reached."""
    # Monkeypatch max_concurrent_runs to 1 for this test
    monkeypatch.setattr(settings, "max_concurrent_runs", 1)
    # The production guard reads persisted state, so the test must create a
    # persisted running row rather than relying on process-local cache state.
    with mock_db.SessionLocal() as session:
        session.add(RunRecord(
            run_id="existing-run",
            target_id="http://host.docker.internal:9000/chat",
            status="running",
        ))
        session.commit()

    response = client.post(
        "/api/runs",
        json={"target_id": verified_target.target_id, "strategy": "Prompt Injection", "intensity": "Low"},
    )
    assert response.status_code == 429
    data = response.json()
    assert "concurrent" in data["detail"].lower()


def test_create_run_concurrency_cap_ignores_non_running(mock_db, monkeypatch, verified_target):
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
            json={"target_id": verified_target.target_id, "strategy": "Prompt Injection", "intensity": "Low"},
        )
        # The target is verified and no run is "running", so it must start.
        assert response.status_code == 200
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
