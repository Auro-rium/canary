"""API v2 target registration + ownership verification, and the campaign gate.

No real network: ownership checks run over ``httpx.MockTransport`` with fake
DNS resolvers, and the legacy orchestrator thread is stubbed.
"""

import uuid
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from cyberredteam import api
from cyberredteam.api import app, get_ownership_options, get_target_store, settings
from cyberredteam.security.crypto import generate_key
from cyberredteam.security.ownership import VERIFY_HEADER
from cyberredteam.security.targets import InMemoryTargetStore

client = TestClient(app)

BEARER_SECRET = "sk-live-BEARER-SECRET-123"
ENDPOINT = "https://agent.example.com/v1/chat"


class FakeOwnedTarget:
    """Publishes whatever token it is told to, via all three channels."""

    def __init__(self):
        self.token: str | None = None
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.path == "/.well-known/canary-verify.txt":
            return httpx.Response(200, text=self.token or "") if self.token else httpx.Response(404)
        headers = {VERIFY_HEADER: self.token} if self.token else {}
        return httpx.Response(200, headers=headers, json={"reply": "hello"})

    def txt(self, name, timeout):
        return [self.token] if self.token and name == "_canary-verify.agent.example.com" else []


@pytest.fixture
def owned(monkeypatch, tmp_path):
    monkeypatch.setenv("CANARY_ENCRYPTION_KEY", generate_key())
    monkeypatch.setattr(settings, "db_path", Path(tmp_path) / "api_v2.db")
    monkeypatch.setattr(settings, "allowed_targets", "")
    monkeypatch.setattr(api, "run_orchestrator_thread", lambda *a, **k: None)
    store = InMemoryTargetStore()
    fake = FakeOwnedTarget()
    app.dependency_overrides[get_target_store] = lambda: store
    app.dependency_overrides[get_ownership_options] = lambda: {
        "allow_private_targets": False,
        "transport": httpx.MockTransport(fake.handler),
        "resolve_host": lambda host: ["93.184.216.34"],
        "txt_resolver": fake.txt,
    }
    yield fake, store
    app.dependency_overrides.pop(get_target_store, None)
    app.dependency_overrides.pop(get_ownership_options, None)


def target_body(**overrides):
    body = {
        "name": "Support agent",
        "endpoint": ENDPOINT,
        "auth": {"type": "bearer", "token": BEARER_SECRET},
        "request_template": '{"input": "{{MESSAGE}}"}',
        "response_path": "reply",
        "session_mode": "stateless_history",
        "environment": "staging",
    }
    body.update(overrides)
    return body


def register(**overrides):
    resp = client.post("/api/v2/targets", json=target_body(**overrides))
    assert resp.status_code == 201, resp.text
    return resp.json()


# ── registration ─────────────────────────────────────────────────────────────


def test_create_returns_masked_target_and_token_once(owned):
    fake, store = owned
    resp = client.post("/api/v2/targets", json=target_body())
    assert resp.status_code == 201
    assert BEARER_SECRET not in resp.text
    data = resp.json()
    token = data["verification_token"]
    assert len(token) > 40
    assert data["target"]["verified"] is False
    assert data["target"]["auth"]["token"] == "**********"
    assert data["verification"]["dns_txt"]["name"] == "_canary-verify.agent.example.com"
    assert data["verification"]["http_wellknown"]["url"] == (
        "https://agent.example.com/.well-known/canary-verify.txt"
    )
    tid = data["target"]["target_id"]
    # Only the hash is stored; GET responses never carry the token or secret.
    assert store.get_verification_token_hash(tid) != token
    for path in (f"/api/v2/targets/{tid}", "/api/v2/targets"):
        got = client.get(path)
        assert got.status_code == 200
        assert token not in got.text
        assert BEARER_SECRET not in got.text


def test_client_supplied_verified_and_id_ignored(owned):
    _, store = owned
    chosen = str(uuid.uuid4())
    data = register(verified=True, target_id=chosen)
    tid = data["target"]["target_id"]
    assert tid != chosen
    assert data["target"]["verified"] is False
    assert store.get(tid).verified is False
    assert client.get(f"/api/v2/targets/{tid}").json()["verified"] is False


def test_validation_error_never_echoes_secrets(owned):
    resp = client.post(
        "/api/v2/targets",
        json=target_body(session_mode="bogus", auth={"type": "bearer", "token": BEARER_SECRET}),
    )
    assert resp.status_code == 422
    assert BEARER_SECRET not in resp.text
    resp = client.post("/api/v2/targets", json=[{"token": BEARER_SECRET}])
    assert resp.status_code == 422
    assert BEARER_SECRET not in resp.text


def test_mask_value_rejected_as_secret(owned):
    resp = client.post(
        "/api/v2/targets", json=target_body(auth={"type": "bearer", "token": "**********"})
    )
    assert resp.status_code == 422


def test_create_without_encryption_key_fails_closed(owned, monkeypatch):
    from cyberredteam.security import crypto

    monkeypatch.setattr(
        crypto, "get_settings", lambda: type("S", (), {"canary_encryption_key": None})()
    )
    resp = client.post("/api/v2/targets", json=target_body())
    assert resp.status_code == 503
    assert BEARER_SECRET not in resp.text


@pytest.mark.parametrize(
    "endpoint, wellknown",
    [
        ("https://agent.example.com/c", "https://agent.example.com/.well-known/canary-verify.txt"),
        ("https://agent.example.com:443/c", "https://agent.example.com/.well-known/canary-verify.txt"),
        ("http://agent.example.com:443/c", "http://agent.example.com:443/.well-known/canary-verify.txt"),
        ("https://agent.example.com:80/c", "https://agent.example.com:80/.well-known/canary-verify.txt"),
        ("https://agent.example.com:8443/c", "https://agent.example.com:8443/.well-known/canary-verify.txt"),
    ],
)
def test_wellknown_instructions_keep_non_default_port(owned, endpoint, wellknown):
    data = register(endpoint=endpoint)
    assert data["verification"]["http_wellknown"]["url"] == wellknown


def test_private_endpoint_refused_at_registration(owned):
    resp = client.post("/api/v2/targets", json=target_body(endpoint="http://127.0.0.1:9000/chat"))
    assert resp.status_code == 422
    assert "refused" in resp.text


def test_get_unknown_target_404(owned):
    assert client.get(f"/api/v2/targets/{uuid.uuid4()}").status_code == 404


# ── auth URL host binding (token_url / login_url) ────────────────────────────


def oauth(token_url):
    return {
        "type": "oauth_client_credentials",
        "token_url": token_url,
        "client_id": "cid",
        "client_secret": "oauth-SECRET",
    }


def test_oauth_token_url_on_endpoint_host_allowed(owned):
    data = register(auth=oauth("https://agent.example.com/oauth/token"))
    assert data["target"]["auth"]["client_secret"] == "**********"


def test_oauth_token_url_on_sibling_subdomain_needs_listing(owned):
    resp = client.post(
        "/api/v2/targets", json=target_body(auth=oauth("https://auth.example.com/oauth/token"))
    )
    assert resp.status_code == 422
    data = register(
        auth=oauth("https://auth.example.com/oauth/token"), allowed_auth_hosts=["auth.example.com"]
    )
    assert data["target"]["allowed_auth_hosts"] == ["auth.example.com"]


def test_oauth_token_url_cross_tenant_shared_hosting_refused(owned):
    resp = client.post(
        "/api/v2/targets",
        json=target_body(
            endpoint="https://victim.herokuapp.com/chat",
            auth=oauth("https://attacker.herokuapp.com/token"),
        ),
    )
    assert resp.status_code == 422


def test_oauth_token_url_on_foreign_host_refused(owned):
    resp = client.post(
        "/api/v2/targets", json=target_body(auth=oauth("https://attacker.example.net/token"))
    )
    assert resp.status_code == 422
    assert "allowed_auth_hosts" in resp.text
    assert "oauth-SECRET" not in resp.text


def test_foreign_auth_host_allowed_when_listed(owned):
    data = register(
        auth=oauth("https://login.idp.example.org/token"),
        allowed_auth_hosts=["login.idp.example.org"],
    )
    assert data["target"]["allowed_auth_hosts"] == ["login.idp.example.org"]


def test_cookie_login_url_private_refused(owned):
    auth = {
        "type": "cookie_login",
        "login_url": "http://169.254.169.254/login",
        "username": "u",
        "password": "pw-SECRET",
    }
    resp = client.post(
        "/api/v2/targets", json=target_body(auth=auth, allowed_auth_hosts=["169.254.169.254"])
    )
    assert resp.status_code == 422
    assert "pw-SECRET" not in resp.text


def test_bad_allowed_auth_hosts_rejected(owned):
    resp = client.post(
        "/api/v2/targets", json=target_body(allowed_auth_hosts=["https://x.example.org/"])
    )
    assert resp.status_code == 422


# ── verification ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize("method", ["http_wellknown", "dns_txt", "response_header"])
def test_verify_each_method(owned, method):
    fake, store = owned
    data = register()
    tid = data["target"]["target_id"]
    fake.token = data["verification_token"]
    resp = client.post(f"/api/v2/targets/{tid}/verify", json={"method": method})
    assert resp.status_code == 200
    body = resp.json()
    assert body["verified"] is True, body["reason"]
    assert body["target"]["verified"] is True
    assert BEARER_SECRET not in resp.text
    assert store.get(tid).verified is True


def test_verify_wrong_token_stays_unverified(owned):
    fake, store = owned
    tid = register()["target"]["target_id"]
    fake.token = "canary-verify-not-the-right-token"
    resp = client.post(f"/api/v2/targets/{tid}/verify", json={"method": "http_wellknown"})
    assert resp.status_code == 200
    assert resp.json()["verified"] is False
    assert store.get(tid).verified is False


def test_verify_bad_method_and_unknown_target(owned):
    tid = register()["target"]["target_id"]
    assert client.post(f"/api/v2/targets/{tid}/verify", json={"method": "telepathy"}).status_code == 422
    assert (
        client.post(f"/api/v2/targets/{uuid.uuid4()}/verify", json={"method": "dns_txt"}).status_code
        == 404
    )


def test_verify_refuses_target_that_now_resolves_private(owned):
    fake, store = owned
    data = register()
    tid = data["target"]["target_id"]
    fake.token = data["verification_token"]
    app.dependency_overrides[get_ownership_options] = lambda: {
        "transport": httpx.MockTransport(fake.handler),
        "resolve_host": lambda host: ["10.0.0.7"],
        "txt_resolver": fake.txt,
    }
    resp = client.post(f"/api/v2/targets/{tid}/verify", json={"method": "dns_txt"})
    assert resp.json()["verified"] is False
    assert resp.json()["reason"].startswith("refused")
    assert store.get(tid).verified is False


# ── campaign gate ────────────────────────────────────────────────────────────


def run_body(target_id):
    return {"target_id": target_id, "strategy": "Prompt Injection", "intensity": "Low"}


def test_create_verify_then_campaign_allowed(owned):
    fake, _ = owned
    data = register()
    tid = data["target"]["target_id"]
    # Unverified → 403
    assert client.post("/api/runs", json=run_body(tid)).status_code == 403
    fake.token = data["verification_token"]
    assert client.post(f"/api/v2/targets/{tid}/verify", json={"method": "response_header"}).json()[
        "verified"
    ]
    resp = client.post("/api/runs", json=run_body(tid))
    assert resp.status_code == 200, resp.text
    assert resp.json()["endpoint"] == ENDPOINT


def test_unverified_target_refused_on_both_legacy_routes(owned):
    tid = register()["target"]["target_id"]
    assert client.post("/api/runs", json=run_body(tid)).status_code == 403
    resp = client.post(
        "/api/campaigns/run",
        json={"campaign_id": "c1", "target_id": tid, "techniques": ["prompt-injection"]},
    )
    assert resp.status_code == 403
    resp = client.post(
        "/api/campaigns/run",
        json={"campaign_id": "c1", "target_url": ENDPOINT, "techniques": ["prompt-injection"]},
    )
    assert resp.status_code == 403


def test_unregistered_ids_and_urls_refused(owned):
    assert client.post("/api/runs", json=run_body(str(uuid.uuid4()))).status_code == 403
    assert client.post("/api/runs", json=run_body("not-a-uuid")).status_code == 403
    assert client.post("/api/runs", json=run_body("")).status_code == 403


@pytest.mark.parametrize("url", ["", "http://localhost:9000/chat", "http://127.0.0.1:9000/chat"])
def test_legacy_localhost_rewrite_is_gone(owned, url):
    """Empty/localhost URLs used to be silently rewritten to host.docker.internal
    and attacked. They must now be refused like any unregistered target."""
    resp = client.post(
        "/api/campaigns/run",
        json={"campaign_id": "c1", "target_url": url, "techniques": ["prompt-injection"]},
    )
    assert resp.status_code == 403


def test_allowlist_narrows_but_never_opens(owned, monkeypatch):
    fake, store = owned
    data = register()
    tid = data["target"]["target_id"]
    store.set_verified(tid, "dns_txt")
    monkeypatch.setattr(settings, "allowed_targets", str(uuid.uuid4()))
    assert client.post("/api/runs", json=run_body(tid)).status_code == 403
    monkeypatch.setattr(settings, "allowed_targets", tid)
    assert client.post("/api/runs", json=run_body(tid)).status_code == 200
    # An allowlisted but unregistered target is still refused.
    other = str(uuid.uuid4())
    monkeypatch.setattr(settings, "allowed_targets", other)
    assert client.post("/api/runs", json=run_body(other)).status_code == 403


def test_refusal_does_not_leak_concurrency_slot(owned):
    tid = register()["target"]["target_id"]
    before = dict(api.active_runs)
    assert client.post("/api/runs", json=run_body(tid)).status_code == 403
    assert api.active_runs == before
