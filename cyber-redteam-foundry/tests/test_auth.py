"""WP8 authentication: API keys (hash-only, constant-time), sessions + CSRF, the
app-wide gate, and the deprecated v1 read routes.

These use the real ``require_auth``/``get_principal`` (the ``v2`` fixture removes
the conftest bypass).
"""

from __future__ import annotations

import hmac
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import select

from cyberredteam.api import app, settings
from cyberredteam.auth import tokens
from cyberredteam.auth.tables import ApiKeyRow, AuthSessionRow
from cyberredteam.storage.v2.db import session_scope


def test_no_credentials_and_bad_credentials_are_401(v2):
    c = v2.client
    assert c.get("/api/v2/me").status_code == 401
    assert c.get("/api/v2/me", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert c.get("/api/v2/me", headers={"Authorization": "Basic abc"}).status_code == 401
    assert c.get("/api/v2/me", headers={"X-API-Key": "cnry_0000000000000000_" + "x" * 43}).status_code == 401
    # the old shared API_SECRET_KEY no longer means anything
    assert c.get("/api/v2/me", headers={"Authorization": "Bearer change-me"}).status_code == 401


def test_api_key_header_forms(v2):
    actor = v2.actor("operator")
    for headers in ({"Authorization": f"Bearer {actor.api_key}"}, {"X-API-Key": actor.api_key}):
        me = v2.client.get("/api/v2/me", headers=headers)
        assert me.status_code == 200
        body = me.json()
        assert body["user_id"] == actor.user_id and body["role"] == "operator"
        assert body["org_id"] == v2.orgs["a"] and body["auth_method"] == "api_key"
        assert "campaigns:launch" in body["permissions"]
        assert "evidence:read_raw" not in body["permissions"]


def test_invalid_key_never_falls_back_to_the_cookie(v2):
    actor = v2.actor("admin")
    headers = {**actor.headers("session"), "Authorization": "Bearer nope"}
    assert v2.client.get("/api/v2/me", headers=headers).status_code == 401


def test_only_key_hashes_are_stored(v2):
    actor = v2.actor("viewer")
    with session_scope(v2.factory) as s:
        rows = s.scalars(select(ApiKeyRow)).all()
        sessions = s.scalars(select(AuthSessionRow)).all()
        dump = repr([(r.key_id, r.key_hash, r.name) for r in rows])
        dump += repr([(r.session_hash, r.csrf_hash) for r in sessions])
    assert actor.api_key not in dump and actor.session not in dump and actor.csrf not in dump
    key_id = tokens.parse_api_key(actor.api_key)
    row = next(r for r in rows if r.key_id == key_id)
    assert row.key_hash == tokens.sha256_hex(actor.api_key)


def test_key_comparison_is_constant_time(v2, monkeypatch):
    calls = []
    real = hmac.compare_digest

    def spy(a, b):
        calls.append((len(a), len(b)))
        return real(a, b)

    monkeypatch.setattr(tokens.hmac, "compare_digest", spy)
    actor = v2.actor("viewer")
    assert v2.client.get("/api/v2/me", headers=actor.headers()).status_code == 200
    # unknown key id: still a (dummy) constant-time comparison, same lengths
    unknown = "cnry_ffffffffffffffff_" + "A" * 43
    assert v2.client.get("/api/v2/me", headers={"X-API-Key": unknown}).status_code == 401
    # right id, wrong secret
    forged = actor.api_key[:-4] + "AAAA"
    assert v2.client.get("/api/v2/me", headers={"X-API-Key": forged}).status_code == 401
    assert len(calls) == 3 and len(set(calls)) == 1


def test_revoked_expired_and_disabled_keys_are_refused(v2):
    actor = v2.actor("operator")
    key_id, key = v2.auth.create_api_key(actor.user_id, "short")
    h = {"X-API-Key": key}
    assert v2.client.get("/api/v2/me", headers=h).status_code == 200
    assert v2.auth.revoke_api_key(actor.user_id, key_id)
    assert v2.client.get("/api/v2/me", headers=h).status_code == 401

    key_id, key = v2.auth.create_api_key(actor.user_id, "old")
    with session_scope(v2.factory) as s:
        s.get(ApiKeyRow, key_id).expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    assert v2.client.get("/api/v2/me", headers={"X-API-Key": key}).status_code == 401

    v2.auth.set_disabled(actor.user_id, True)
    assert v2.client.get("/api/v2/me", headers=actor.headers()).status_code == 401
    assert v2.client.get("/api/v2/me", headers=actor.headers("session")).status_code == 401


def test_role_change_applies_to_existing_keys(v2):
    actor = v2.actor("viewer")
    tid = v2.target()
    body = {"target_id": tid, "policy": {"techniques": ["prompt_injection"]}}
    assert v2.client.post("/api/v2/campaigns", json=body, headers=actor.headers()).status_code == 403
    v2.auth.set_role(actor.user_id, "operator")
    assert v2.client.post("/api/v2/campaigns", json=body, headers=actor.headers()).status_code == 201


def test_session_cookie_needs_csrf_on_unsafe_methods(v2):
    actor = v2.actor("operator")
    cookie_only = {"Cookie": actor.headers("session")["Cookie"]}
    assert v2.client.get("/api/v2/me", headers=cookie_only).status_code == 200  # safe method
    tid = v2.target()
    url = f"/api/v2/targets/{tid}"
    assert v2.client.patch(url, json={"name": "x"}, headers=cookie_only).status_code == 403
    wrong = {**cookie_only, "X-CSRF-Token": "not-it"}
    assert v2.client.patch(url, json={"name": "x"}, headers=wrong).status_code == 403
    assert v2.client.patch(url, json={"name": "x"}, headers=actor.headers("session")).status_code == 200


def test_expired_or_revoked_session_is_401(v2):
    actor = v2.actor("viewer")
    with session_scope(v2.factory) as s:
        row = s.get(AuthSessionRow, tokens.sha256_hex(actor.session))
        row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    assert v2.client.get("/api/v2/me", headers=actor.headers("session")).status_code == 401
    other = v2.actor("operator")
    assert v2.client.post("/api/v2/auth/logout", headers=other.headers("session")).status_code == 200
    assert v2.client.get("/api/v2/me", headers=other.headers("session")).status_code == 401


def test_api_key_self_service(v2):
    actor = v2.actor("viewer")
    created = v2.client.post("/api/v2/auth/api-keys", json={"name": "ci"}, headers=actor.headers("session"))
    assert created.status_code == 201
    key, key_id = created.json()["api_key"], created.json()["key"]["key_id"]
    assert v2.client.get("/api/v2/me", headers={"X-API-Key": key}).json()["role"] == "viewer"
    listed = v2.client.get("/api/v2/auth/api-keys", headers=actor.headers()).text
    assert key_id in listed and key not in listed
    # an API key cannot mint more keys; someone else's key cannot be revoked
    assert v2.client.post("/api/v2/auth/api-keys", json={}, headers={"X-API-Key": key}).status_code == 403
    other = v2.actor("admin")
    assert v2.client.delete(f"/api/v2/auth/api-keys/{key_id}", headers=other.headers()).status_code == 404
    assert v2.client.delete(f"/api/v2/auth/api-keys/{key_id}", headers=actor.headers()).status_code == 200
    assert v2.client.get("/api/v2/me", headers={"X-API-Key": key}).status_code == 401


def test_health_is_public(v2):
    assert TestClient(app).get("/health").json() == {"status": "ok"}


# ── deprecated v1 read routes ────────────────────────────────────────────────


def test_v1_reads_are_admin_only_and_deprecated(v2, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "db_path", tmp_path / "legacy.db")
    assert v2.client.get("/api/runs").status_code == 401
    assert v2.client.get("/api/runs", headers=v2.h("operator")).status_code == 403
    resp = v2.client.get("/api/runs", headers=v2.h("admin"))
    assert resp.status_code == 200
    assert resp.headers["Deprecation"] == "true" and resp.headers["Sunset"] == settings.v1_sunset
    assert "/api/runs" not in app.openapi()["paths"]


def test_v1_flag_off_is_410(v2, monkeypatch):
    monkeypatch.setattr(settings, "v1_api_enabled", False)
    assert v2.client.get("/api/findings", headers=v2.h("admin")).status_code == 410
