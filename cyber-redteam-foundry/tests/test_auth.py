"""Tests for API bearer-token authentication.

These deliberately clear the auth-bypass override installed by conftest so
the real ``require_auth`` dependency runs.
"""

import pytest
from fastapi.testclient import TestClient

from cyberredteam.api import app, require_auth, settings

client = TestClient(app)


@pytest.fixture
def enforce_auth():
    """Remove the conftest bypass and restore the secret key afterward."""
    app.dependency_overrides.pop(require_auth, None)
    original = settings.api_secret_key
    yield
    settings.api_secret_key = original
    app.dependency_overrides[require_auth] = lambda: None


def test_missing_token_rejected(enforce_auth):
    settings.api_secret_key = "s3cret"
    resp = client.get("/api/status")
    assert resp.status_code == 401


def test_wrong_token_rejected(enforce_auth):
    settings.api_secret_key = "s3cret"
    resp = client.get("/api/status", headers={"Authorization": "Bearer nope"})
    assert resp.status_code == 401


def test_valid_token_accepted(enforce_auth):
    settings.api_secret_key = "s3cret"
    resp = client.get("/api/status", headers={"Authorization": "Bearer s3cret"})
    assert resp.status_code == 200


def test_unconfigured_key_fails_closed(enforce_auth):
    settings.api_secret_key = None
    resp = client.get("/api/status", headers={"Authorization": "Bearer anything"})
    assert resp.status_code == 503
