"""Tests for the FastAPI web server endpoints."""

from datetime import datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from cyberredteam.api import app, settings
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


def test_removed_v1_write_routes_are_gone():
    """WP8 removed POST /api/runs, the old SSE POST /api/campaigns/run and the
    v1 finding status write; campaigns start only through /api/v2."""
    assert client.post("/api/runs", json={"target_id": "x"}).status_code in (404, 405)
    assert client.post("/api/campaigns/run", json={"campaign_id": "c"}).status_code in (404, 405)
    assert client.put("/api/findings/f1/status", json={"status": "open"}).status_code in (404, 405)
