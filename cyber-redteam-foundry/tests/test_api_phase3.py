"""Tests for Phase 3 API endpoints: findings CRUD, coverage, trends, run findings."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from cyberredteam.api import app
from cyberredteam.storage.artifact_store import SQLiteStore


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """TestClient with a real SQLiteStore backed by a temp DB."""
    db = tmp_path / "test.db"
    store = SQLiteStore(db)

    # Seed two findings
    store.upsert_finding({
        "finding_id": "f001",
        "run_id": "run001",
        "target_id": "HR Agent",
        "component": "employee_lookup",
        "strategy": "tool_misuse",
        "asi_class": "ASI02",
        "atlas_technique": "AML.T0051.002",
        "severity": "high",
    })
    store.upsert_finding({
        "finding_id": "f002",
        "run_id": "run001",
        "target_id": "HR Agent",
        "component": "document_search",
        "strategy": "indirect_injection",
        "asi_class": "ASI01",
        "atlas_technique": "AML.T0051.000",
        "severity": "critical",
    })
    store.close()

    # Patch SQLiteStore construction in api.py to use our temp DB
    original_init = SQLiteStore.__init__

    def patched_init(self, db_path):
        original_init(self, db)

    monkeypatch.setattr(SQLiteStore, "__init__", patched_init)
    monkeypatch.setattr("cyberredteam.api.settings.db_path", db)

    return TestClient(app)


# ─── GET /api/findings ───────────────────────────────────────────────────────

def test_list_findings_returns_all(client):
    resp = client.get("/api/findings")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2


def test_list_findings_filter_by_asi(client):
    resp = client.get("/api/findings?asi_class=ASI02")
    assert resp.status_code == 200
    data = resp.json()
    assert all(f["asi_class"] == "ASI02" for f in data)


def test_list_findings_filter_by_status(client):
    resp = client.get("/api/findings?status=open")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2


def test_list_findings_filter_by_severity(client):
    resp = client.get("/api/findings?severity=critical")
    assert resp.status_code == 200
    data = resp.json()
    assert all(f["severity"] == "critical" for f in data)


# ─── GET /api/findings/{id} ──────────────────────────────────────────────────

def test_get_finding_by_id(client):
    resp = client.get("/api/findings/f001")
    assert resp.status_code == 200
    data = resp.json()
    assert data["finding_id"] == "f001"
    assert data["component"] == "employee_lookup"


def test_get_finding_not_found(client):
    resp = client.get("/api/findings/doesnotexist")
    assert resp.status_code == 404


# ─── GET /api/findings/{id}/attempts ────────────────────────────────────────

def test_get_finding_attempts_empty(client):
    resp = client.get("/api/findings/f001/attempts")
    assert resp.status_code == 200
    assert resp.json() == []


# ─── PUT /api/findings/{id}/status ──────────────────────────────────────────

def test_update_status_legal_transition(client):
    resp = client.put("/api/findings/f001/status", json={
        "status": "patch_proposed",
        "patch_ref": "patch_001",
    })
    assert resp.status_code == 200
    assert resp.json()["new_status"] == "patch_proposed"


def test_update_status_illegal_transition_returns_409(client):
    resp = client.put("/api/findings/f001/status", json={
        "status": "verified_fixed",
    })
    assert resp.status_code == 409


def test_update_status_wont_fix_missing_reviewer_returns_409(client):
    resp = client.put("/api/findings/f001/status", json={
        "status": "wont_fix",
    })
    assert resp.status_code == 409


def test_update_status_wont_fix_with_metadata(client):
    resp = client.put("/api/findings/f001/status", json={
        "status": "wont_fix",
        "reviewer_id": "alice",
        "rationale": "Accepted business risk — out of scope for this product.",
    })
    assert resp.status_code == 200
    assert resp.json()["new_status"] == "wont_fix"


# ─── GET /api/targets/{id}/coverage ─────────────────────────────────────────

def test_target_coverage(client):
    resp = client.get("/api/targets/HR Agent/coverage")
    assert resp.status_code == 200
    data = resp.json()
    assert "ASI01" in data["tested_classes"]
    assert "ASI02" in data["tested_classes"]
    assert data["total_findings"] == 2


# ─── GET /api/targets/{id}/trends ────────────────────────────────────────────

def test_target_trends_empty_no_attacks(client):
    resp = client.get("/api/targets/HR Agent/trends?days=30")
    assert resp.status_code == 200
    # No attack records seeded → empty trends
    assert resp.json() == []


# ─── GET /api/runs/{id}/findings ─────────────────────────────────────────────

def test_run_findings(client):
    resp = client.get("/api/runs/run001/findings")
    assert resp.status_code == 200
    data = resp.json()
    # Both findings were seeded with run_id="run001"
    assert len(data) == 2


def test_run_findings_unknown_run(client):
    resp = client.get("/api/runs/unknownrun/findings")
    assert resp.status_code == 200
    assert resp.json() == []


# ─── GET /api/open-findings (updated to use store.get_findings) ──────────────

def test_open_findings_uses_new_store(client):
    resp = client.get("/api/open-findings")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2
    assert all(f["status"] == "open" for f in data)
