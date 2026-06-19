"""Tests for the FastAPI web server endpoints."""

import pytest
from fastapi.testclient import TestClient
from cyberredteam.api import app, settings
from cyberredteam.storage.artifact_store import SQLiteStore
from cyberredteam.storage.models import RunRecord, AttackRecord, PatchRecord
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

        # Patch
        patch = PatchRecord(
            run_id="testrun123",
            patch_id="patch-0",
            patch_type="prompt_hardening",
            target_component="finance_agent",
            original_config={},
            patched_config={},
            diff="diff config",
            applied=0,
            retest_passed=1,
        )
        session.add(patch)
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
    assert len(data["patches"]) == 1

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
    assert "suggestedYaml" in data


def test_apply_policy(mock_db):
    """Test applying generated policy patches."""
    response = client.get("/api/runs/testrun123")
    assert response.json()["patches"][0]["applied"] is False

    response_apply = client.post("/api/runs/testrun123/apply")
    assert response_apply.status_code == 200
    assert response_apply.json()["status"] == "success"

    response_after = client.get("/api/runs/testrun123")
    assert response_after.json()["patches"][0]["applied"] is True


def test_create_run_endpoint(mock_db):
    """Test creating/triggering a run."""
    response = client.post(
        "/api/runs",
        json={"target_id": "HR Agent", "strategy": "Prompt Injection", "intensity": "Low"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "run_id" in data
    assert data["status"] == "running"
    assert data["target_id"] == "HR Agent"
