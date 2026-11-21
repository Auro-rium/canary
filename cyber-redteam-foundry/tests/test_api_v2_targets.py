"""/api/v2/targets on the SQL store: registration, verification, update, delete,
the on-call webhook, and org isolation (WP1 tests ported to WP8 auth).

No real network: ownership checks run over ``httpx.MockTransport`` with fake DNS
resolvers (see ``api_v2_support``).
"""

from __future__ import annotations

import uuid

import pytest
from api_v2_support import ENDPOINT

from cyberredteam.api import app
from cyberredteam.api_v2.deps import get_ownership_options
from cyberredteam.storage.v2.repositories import AuditRepo, SqlTargetStore

BEARER_SECRET = "sk-live-BEARER-SECRET-123"
WEBHOOK = "https://hooks.slack.com/services/T000/B000/WEBHOOK-SECRET-xyz"


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


@pytest.fixture
def op(v2):
    """POST/GET/PATCH/DELETE helpers as org A's operator."""
    h = v2.h("operator")

    class Op:
        def post(self, url, **kw):
            return v2.client.post(url, headers=h, **kw)

        def get(self, url, **kw):
            return v2.client.get(url, headers=h, **kw)

        def patch(self, url, **kw):
            return v2.client.patch(url, headers=h, **kw)

        def delete(self, url, **kw):
            return v2.client.delete(url, headers=h, **kw)

        def register(self, **overrides):
            resp = self.post("/api/v2/targets", json=target_body(**overrides))
            assert resp.status_code == 201, resp.text
            return resp.json()

        def verify(self, data, method="response_header"):
            v2.owned.token = data["verification_token"]
            tid = data["target"]["target_id"]
            resp = self.post(f"/api/v2/targets/{tid}/verify", json={"method": method})
            assert resp.json()["verified"] is True, resp.text
            return tid

    return Op()


def store(v2) -> SqlTargetStore:
    return SqlTargetStore(v2.factory)


# ── registration ─────────────────────────────────────────────────────────────


def test_create_returns_masked_target_and_token_once(v2, op):
    resp = op.post("/api/v2/targets", json=target_body())
    assert resp.status_code == 201
    assert BEARER_SECRET not in resp.text
    data = resp.json()
    token = data["verification_token"]
    assert len(token) > 40
    assert data["target"]["verified"] is False
    assert data["target"]["auth"]["token"] == "**********"
    assert data["verification"]["dns_txt"]["name"] == "_canary-verify.agent.example.com"
    tid = data["target"]["target_id"]
    assert store(v2).meta(tid).org_id == v2.orgs["a"]
    # Only the hash is stored; GET responses never carry the token or secret.
    assert store(v2).get_verification_token_hash(tid) != token
    for path in (f"/api/v2/targets/{tid}", "/api/v2/targets"):
        got = op.get(path)
        assert got.status_code == 200
        assert token not in got.text and BEARER_SECRET not in got.text
    assert [e.actor for e in AuditRepo(v2.factory).list(action="target.create")] == [
        v2.actor("operator").actor
    ]


def test_client_supplied_verified_and_id_ignored(v2, op):
    chosen = str(uuid.uuid4())
    data = op.register(verified=True, target_id=chosen)
    tid = data["target"]["target_id"]
    assert tid != chosen and data["target"]["verified"] is False
    assert store(v2).get(tid).verified is False


def test_unknown_fields_rejected(op):
    assert op.post("/api/v2/targets", json=target_body(org_id="other")).status_code == 422


def test_validation_error_never_echoes_secrets(op):
    resp = op.post(
        "/api/v2/targets",
        json=target_body(session_mode="bogus", auth={"type": "bearer", "token": BEARER_SECRET}),
    )
    assert resp.status_code == 422 and BEARER_SECRET not in resp.text
    resp = op.post("/api/v2/targets", json=[{"token": BEARER_SECRET}])
    assert resp.status_code == 422 and BEARER_SECRET not in resp.text
    resp = op.post("/api/v2/targets", json=target_body(request_template=f'{{"k": "{BEARER_SECRET}"}}'))
    assert resp.status_code == 422 and BEARER_SECRET not in resp.text


def test_mask_value_rejected_as_secret(op):
    resp = op.post("/api/v2/targets", json=target_body(auth={"type": "bearer", "token": "**********"}))
    assert resp.status_code == 422


def test_create_without_encryption_key_fails_closed(v2, op, monkeypatch):
    from cyberredteam.storage.v2 import encrypted

    monkeypatch.delenv("CANARY_ENCRYPTION_KEY")
    encrypted.reset_key_cache()
    resp = op.post("/api/v2/targets", json=target_body())
    assert resp.status_code == 503
    assert BEARER_SECRET not in resp.text
    assert "agent.example.com" not in op.get("/api/v2/targets").text  # nothing half-stored


@pytest.mark.parametrize(
    "endpoint, wellknown",
    [
        ("https://agent.example.com/c", "https://agent.example.com/.well-known/canary-verify.txt"),
        ("https://agent.example.com:443/c", "https://agent.example.com/.well-known/canary-verify.txt"),
        ("http://agent.example.com:443/c", "http://agent.example.com:443/.well-known/canary-verify.txt"),
        ("https://agent.example.com:8443/c", "https://agent.example.com:8443/.well-known/canary-verify.txt"),
    ],
)
def test_wellknown_instructions_keep_non_default_port(op, endpoint, wellknown):
    assert op.register(endpoint=endpoint)["verification"]["http_wellknown"]["url"] == wellknown


def test_private_endpoint_refused_at_registration(op):
    resp = op.post("/api/v2/targets", json=target_body(endpoint="http://127.0.0.1:9000/chat"))
    assert resp.status_code == 422 and "refused" in resp.text


def test_get_unknown_target_404(op):
    assert op.get(f"/api/v2/targets/{uuid.uuid4()}").status_code == 404


# ── auth URL host binding (token_url / login_url) ────────────────────────────


def oauth(token_url, secret="oauth-SECRET"):
    return {"type": "oauth_client_credentials", "token_url": token_url, "client_id": "cid",
            "client_secret": secret}


def test_oauth_token_url_host_binding(op):
    assert op.register(auth=oauth("https://agent.example.com/oauth/token"))["target"]["auth"][
        "client_secret"] == "**********"
    sibling = target_body(auth=oauth("https://auth.example.com/oauth/token"))
    assert op.post("/api/v2/targets", json=sibling).status_code == 422
    data = op.register(auth=oauth("https://auth.example.com/oauth/token"),
                       allowed_auth_hosts=["auth.example.com"])
    assert data["target"]["allowed_auth_hosts"] == ["auth.example.com"]
    foreign = op.post("/api/v2/targets", json=target_body(auth=oauth("https://attacker.example.net/t")))
    assert foreign.status_code == 422 and "oauth-SECRET" not in foreign.text
    heroku = target_body(endpoint="https://victim.herokuapp.com/chat",
                         auth=oauth("https://attacker.herokuapp.com/token"))
    assert op.post("/api/v2/targets", json=heroku).status_code == 422


def test_cookie_login_url_private_refused(op):
    auth = {"type": "cookie_login", "login_url": "http://169.254.169.254/login", "username": "u",
            "password": "pw-SECRET"}
    resp = op.post("/api/v2/targets", json=target_body(auth=auth, allowed_auth_hosts=["169.254.169.254"]))
    assert resp.status_code == 422 and "pw-SECRET" not in resp.text


def test_bad_allowed_auth_hosts_rejected(op):
    assert op.post("/api/v2/targets", json=target_body(allowed_auth_hosts=["https://x.example.org/"])
                   ).status_code == 422


# ── verification ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize("method", ["http_wellknown", "dns_txt", "response_header"])
def test_verify_each_method(v2, op, method):
    data = op.register()
    tid = op.verify(data, method)
    assert store(v2).get(tid).verified is True
    assert store(v2).meta(tid).verified_method == method
    assert op.get(f"/api/v2/targets/{tid}").json()["verified_method"] == method


def test_verify_wrong_token_stays_unverified(v2, op):
    tid = op.register()["target"]["target_id"]
    v2.owned.token = "canary-verify-not-the-right-token"
    resp = op.post(f"/api/v2/targets/{tid}/verify", json={"method": "http_wellknown"})
    assert resp.status_code == 200 and resp.json()["verified"] is False
    assert store(v2).get(tid).verified is False


def test_verify_bad_method_and_unknown_target(op):
    tid = op.register()["target"]["target_id"]
    assert op.post(f"/api/v2/targets/{tid}/verify", json={"method": "telepathy"}).status_code == 422
    assert op.post(f"/api/v2/targets/{uuid.uuid4()}/verify", json={"method": "dns_txt"}).status_code == 404


def test_verify_refuses_target_that_now_resolves_private(v2, op):
    data = op.register()
    tid = data["target"]["target_id"]
    v2.owned.token = data["verification_token"]
    app.dependency_overrides[get_ownership_options] = lambda: {
        **v2.ownership, "resolve_host": lambda host: ["10.0.0.7"],
    }
    resp = op.post(f"/api/v2/targets/{tid}/verify", json={"method": "dns_txt"})
    assert resp.json()["verified"] is False and resp.json()["reason"].startswith("refused")
    assert store(v2).get(tid).verified is False


# ── update ───────────────────────────────────────────────────────────────────


def test_rotating_only_the_secret_keeps_verification(v2, op):
    tid = op.verify(op.register())
    resp = op.patch(f"/api/v2/targets/{tid}", json={"auth": {"type": "bearer", "token": "sk-NEW-777"}})
    assert resp.status_code == 200, resp.text
    assert resp.json()["verification_reset"] is False and resp.json()["target"]["verified"] is True
    assert "sk-NEW-777" not in resp.text
    assert store(v2).get(tid).auth.token.get_secret_value() == "sk-NEW-777"


def test_omitted_secret_keeps_the_stored_one(v2, op):
    tid = op.verify(op.register(auth=oauth("https://agent.example.com/token", "keep-ME-1")))
    resp = op.patch(f"/api/v2/targets/{tid}", json={"auth": {
        "type": "oauth_client_credentials", "token_url": "https://agent.example.com/token",
        "client_id": "cid", "scope": "chat"}})
    assert resp.status_code == 200, resp.text
    auth = store(v2).get(tid).auth
    assert auth.client_secret.get_secret_value() == "keep-ME-1" and auth.scope == "chat"
    assert resp.json()["verification_reset"] is True  # a non-secret auth field changed
    assert op.patch(f"/api/v2/targets/{tid}", json={"auth": {"type": "bearer", "token": "**********"}}
                    ).status_code == 422


@pytest.mark.parametrize("change", [
    {"endpoint": "https://agent.example.com/v2/chat"},
    {"auth": {"type": "header", "header_name": "X-Key", "value": "v-SECRET-1"}},
    {"allowed_auth_hosts": ["auth.example.com"]},
])
def test_security_relevant_changes_clear_verification(v2, op, change):
    tid = op.verify(op.register())
    resp = op.patch(f"/api/v2/targets/{tid}", json=change)
    assert resp.status_code == 200, resp.text
    assert resp.json()["verification_reset"] is True
    assert store(v2).get(tid).verified is False
    assert store(v2).meta(tid).verified_method is None


def test_repointing_endpoint_at_a_private_host_is_refused(v2, op):
    tid = op.verify(op.register())
    assert op.patch(f"/api/v2/targets/{tid}", json={"endpoint": "http://127.0.0.1/x"}).status_code == 422
    assert store(v2).get(tid).verified is True  # nothing changed


def test_environment_is_immutable_and_name_change_keeps_verification(v2, op):
    tid = op.verify(op.register(environment="production"))
    assert op.patch(f"/api/v2/targets/{tid}", json={"environment": "staging"}).status_code == 422
    resp = op.patch(f"/api/v2/targets/{tid}", json={"name": "Renamed", "timeout_s": 30})
    assert resp.json()["verification_reset"] is False
    assert store(v2).get(tid).environment == "production"


# ── on-call webhook (WP11 field) ─────────────────────────────────────────────


def test_webhook_is_write_only_and_encrypted(v2, op):
    data = op.register(oncall_webhook_url=WEBHOOK)
    tid = data["target"]["target_id"]
    assert data["target"]["oncall_webhook_configured"] is True
    for resp in (op.get(f"/api/v2/targets/{tid}"), op.get("/api/v2/targets")):
        assert "WEBHOOK-SECRET" not in resp.text and "hooks.slack.com" not in resp.text
    assert store(v2).get_oncall_webhook(tid) == WEBHOOK
    from sqlalchemy import text

    with v2.factory() as s:
        raw = s.execute(text("SELECT oncall_webhook FROM targets WHERE target_id = :t"), {"t": tid}).scalar()
    assert raw and "WEBHOOK-SECRET" not in raw  # Fernet ciphertext at rest
    assert "WEBHOOK-SECRET" not in repr(AuditRepo(v2.factory).list())
    cleared = op.patch(f"/api/v2/targets/{tid}", json={"oncall_webhook_url": None})
    assert cleared.json()["target"]["oncall_webhook_configured"] is False


def test_private_webhook_refused(op):
    resp = op.post("/api/v2/targets", json=target_body(oncall_webhook_url="http://169.254.169.254/hook"))
    assert resp.status_code == 422


# ── delete ───────────────────────────────────────────────────────────────────


def test_delete_hard_archive_and_active_conflict(v2, op):
    plain = op.register()["target"]["target_id"]
    assert op.delete(f"/api/v2/targets/{plain}").json()["status"] == "deleted"
    assert store(v2).get(plain) is None

    used = op.verify(op.register())
    running = v2.campaign(used, status="running")
    assert op.delete(f"/api/v2/targets/{used}").status_code == 409
    from cyberredteam.storage.v2.repositories import CampaignRepo

    CampaignRepo(v2.factory).set_status(running, "completed")
    assert op.delete(f"/api/v2/targets/{used}").json()["status"] == "archived"
    assert op.get(f"/api/v2/targets/{used}").status_code == 404
    assert used not in op.get("/api/v2/targets").text
    archived = store(v2).get(used)
    assert archived.verified is False and archived.auth.type == "none"  # credentials dropped
    body = {"target_id": used, "policy": {"techniques": ["prompt_injection"]}}
    assert op.post("/api/v2/campaigns", json=body).status_code == 404


# ── org isolation ────────────────────────────────────────────────────────────


def test_other_org_cannot_see_or_touch_a_target(v2, op):
    tid = op.verify(op.register())
    b = v2.h("admin", "b")
    assert tid not in v2.client.get("/api/v2/targets", headers=b).text
    assert v2.client.get(f"/api/v2/targets/{tid}", headers=b).status_code == 404
    assert v2.client.patch(f"/api/v2/targets/{tid}", json={"name": "x"}, headers=b).status_code == 404
    assert v2.client.post(f"/api/v2/targets/{tid}/verify", json={"method": "dns_txt"}, headers=b
                          ).status_code == 404
    assert v2.client.delete(f"/api/v2/targets/{tid}", headers=b).status_code == 404
    assert store(v2).get(tid).name == "Support agent"


def test_legacy_targets_without_org_are_invisible(v2, op):
    tid = v2.target(org=None)
    for role in ("viewer", "admin"):
        assert v2.client.get(f"/api/v2/targets/{tid}", headers=v2.h(role)).status_code == 404


def test_viewer_cannot_register_or_verify(v2):
    h = v2.h("viewer")
    assert v2.client.post("/api/v2/targets", json=target_body(), headers=h).status_code == 403
    assert v2.client.post(f"/api/v2/targets/{v2.target()}/verify", json={"method": "dns_txt"}, headers=h
                          ).status_code == 403
