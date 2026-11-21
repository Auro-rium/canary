"""Backend pieces for the redesigned UI: /me.is_platform_admin, test-connection,
and the campaign compare (gate) route. No real network: probes go over
``httpx.MockTransport`` and a fake DNS resolver (see ``api_v2_support``)."""

from __future__ import annotations

import uuid

import httpx
import pytest
from api_v2_support import ENDPOINT, TARGET_SECRET
from fixtures.fake_target import REQUEST_TEMPLATES, FakeTarget

from cyberredteam.contracts import BearerAuth, TargetConfig, TechniqueResult
from cyberredteam.storage.v2.repositories import AuditRepo, CampaignRepo, SqlTargetStore

# ── /me ──────────────────────────────────────────────────────────────────────


def test_me_reports_platform_admin(v2, monkeypatch):
    monkeypatch.setenv("CANARY_PLATFORM_ADMINS", "admin@a.example")
    assert v2.client.get("/api/v2/me", headers=v2.h("admin")).json()["is_platform_admin"] is True
    # same list, but the org B admin and lower roles are not on it
    for role, org in (("admin", "b"), ("operator", "a"), ("viewer", "a")):
        body = v2.client.get("/api/v2/me", headers=v2.h(role, org)).json()
        assert body["is_platform_admin"] is False
    monkeypatch.setenv("CANARY_PLATFORM_ADMINS", "")
    assert v2.client.get("/api/v2/me", headers=v2.h("admin")).json()["is_platform_admin"] is False


def test_me_flag_is_informational_server_still_enforces(v2, monkeypatch):
    monkeypatch.setenv("CANARY_PLATFORM_ADMINS", "")
    assert v2.client.get("/api/v2/me", headers=v2.h("admin")).json()["is_platform_admin"] is False
    resp = v2.client.post("/api/v2/admin/kill-switch", json={"enabled": True}, headers=v2.h("admin"))
    assert resp.status_code == 403


# ── test-connection ──────────────────────────────────────────────────────────


def _probe(v2, target_id, role="operator", org="a"):
    return v2.client.post(f"/api/v2/targets/{target_id}/test-connection", headers=v2.h(role, org))


def _target_at(v2, url, *, secret=TARGET_SECRET, template=None, org="a") -> str:
    store = SqlTargetStore(v2.factory)
    cfg = TargetConfig(
        target_id=str(uuid.uuid4()), name="probe", endpoint=url, auth=BearerAuth(token=secret),
        request_template=template, response_path="reply",
        session_mode="stateless_history", environment="staging",
    )
    store.create(cfg, org_id=v2.orgs[org])
    return cfg.target_id


def _use_transport(v2, handler):
    v2.ownership["transport"] = httpx.MockTransport(handler)


def test_test_connection_fake_target_happy_path(v2):
    fake = FakeTarget(profile="always_safe")
    v2.ownership["transport"] = fake.async_transport()
    tid = _target_at(v2, fake.url, template=REQUEST_TEMPLATES["stateless_history"])
    resp = _probe(v2, tid)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["parse_ok"] is True and body["http_status"] == 200 and body["error"] is None
    assert body["reply"].startswith("Thanks for your message")
    assert body["latency_ms"] >= 0
    assert len(fake.requests) == 1  # exactly one request reached the target
    sent = fake.requests[0]
    assert sent.body["message"] == "Hello"
    assert sent.headers["x-canary-campaign"].startswith("connection-test:")
    assert TARGET_SECRET not in resp.text


def test_test_connection_works_before_verification(v2):
    fake = FakeTarget()
    v2.ownership["transport"] = fake.async_transport()
    store = SqlTargetStore(v2.factory)
    tid = _target_at(v2, fake.url, template=REQUEST_TEMPLATES["stateless_history"])
    assert store.get(tid).verified is not True
    assert _probe(v2, tid).json()["parse_ok"] is True


def test_test_connection_reports_unparseable_reply(v2):
    _use_transport(v2, lambda req: httpx.Response(200, json={"other": "x"}))
    tid = _target_at(v2, ENDPOINT)
    body = _probe(v2, tid).json()
    assert body["parse_ok"] is False and body["http_status"] in (200, None) and body["reply"] == ""
    assert body["error"]


def test_test_connection_http_error_status(v2):
    _use_transport(v2, lambda req: httpx.Response(403, json={"error": "no"}))
    tid = _target_at(v2, ENDPOINT)
    body = _probe(v2, tid).json()
    assert body["parse_ok"] is False and body["http_status"] == 403 and body["error"] == "http_4xx"


@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data",
    "https://10.1.2.3/chat",
    "https://127.0.0.1:8080/chat",
])
def test_test_connection_refuses_private_hosts(v2, url):
    calls = []
    _use_transport(v2, lambda req: calls.append(req) or httpx.Response(200, json={"reply": "x"}))
    v2.ownership["resolve_host"] = None  # real literal-IP checks, no fake DNS
    tid = _target_at(v2, url)
    resp = _probe(v2, tid)
    assert resp.status_code == 422 and "refused" in resp.text
    assert calls == []
    assert AuditRepo(v2.factory).list(action="target.test_connection") == []


def test_test_connection_cross_org_is_404(v2):
    calls = []
    _use_transport(v2, lambda req: calls.append(req) or httpx.Response(200, json={"reply": "x"}))
    tid = v2.target("a")
    assert _probe(v2, tid, "admin", "b").status_code == 404
    assert calls == []


def test_test_connection_needs_operator(v2):
    tid = v2.target("a")
    assert _probe(v2, tid, "viewer").status_code == 403


def test_test_connection_rate_limited_per_target(v2):
    _use_transport(v2, lambda req: httpx.Response(200, json={"reply": "hi"}))
    t1, t2 = v2.target("a"), v2.target("a")
    assert _probe(v2, t1).status_code == 200
    again = _probe(v2, t1)
    assert again.status_code == 429 and int(again.headers["retry-after"]) >= 1
    assert _probe(v2, t2).status_code == 200  # other targets unaffected
    assert len(AuditRepo(v2.factory).list(action="target.test_connection")) == 2  # 429 not audited


def test_test_connection_redacts_reply_and_target_secrets(v2):
    leaked = "AKIA" "IOSFODNN7EXAMPLE"
    text = f"key {leaked} bearer {TARGET_SECRET} mail jane.doe@example.com"
    _use_transport(v2, lambda req: httpx.Response(200, json={"reply": text}))
    tid = v2.target("a")
    resp = _probe(v2, tid)
    out = resp.json()["reply"]
    assert resp.status_code == 200
    assert leaked not in out and TARGET_SECRET not in out and "jane.doe@example.com" not in out
    assert "REDACTED" in out


def test_test_connection_writes_audit_row_without_secrets(v2):
    _use_transport(v2, lambda req: httpx.Response(200, json={"reply": f"echo {TARGET_SECRET}"}))
    tid = v2.target("a")
    assert _probe(v2, tid).status_code == 200
    rows = AuditRepo(v2.factory).list(action="target.test_connection", obj=f"target:{tid}")
    assert len(rows) == 1
    assert rows[0].actor == f"user:{v2.actor('operator').user_id}"
    assert rows[0].details["parse_ok"] is True
    assert TARGET_SECRET not in str(rows[0].details)


def test_test_connection_sends_one_fixed_message(v2):
    seen = []
    _use_transport(v2, lambda req: seen.append(req.content) or httpx.Response(200, json={"reply": "ok"}))
    tid = v2.target("a")
    assert _probe(v2, tid).status_code == 200
    assert len(seen) == 1 and b"Hello" in seen[0]


# ── compare (gate) ───────────────────────────────────────────────────────────


def _tr(technique, trials, confirmed, low, high):
    return TechniqueResult(technique=technique, trials=trials, confirmed=confirmed,
                           success_rate=confirmed / trials, ci95_low=low, ci95_high=high)


def _seed(v2, rows, org="a", target=None):
    tid = target or v2.target(org)
    cid = v2.campaign(tid, status="completed")
    CampaignRepo(v2.factory).save_technique_results(cid, rows)
    return cid


def _compare(v2, cand, base, role="viewer", org="a"):
    return v2.client.get(f"/api/v2/campaigns/{cand}/compare", params={"baseline": base},
                         headers=v2.h(role, org))


def test_compare_detects_regression(v2):
    tid = v2.target("a")
    base = _seed(v2, [_tr("prompt_injection", 20, 2, 0.03, 0.30)], target=tid)
    cand = _seed(v2, [_tr("prompt_injection", 20, 15, 0.53, 0.89)], target=tid)
    resp = _compare(v2, cand, base)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "regression"
    d = body["diffs"][0]
    assert d["technique"] == "prompt_injection" and d["status"] == "regression"
    assert d["baseline"]["ci95_high"] == 0.30 and d["candidate"]["ci95_low"] == 0.53


def test_compare_pass_and_improved(v2):
    tid = v2.target("a")
    base = _seed(v2, [_tr("a", 20, 10, 0.30, 0.70), _tr("b", 20, 12, 0.39, 0.78)], target=tid)
    cand = _seed(v2, [_tr("a", 20, 9, 0.25, 0.65), _tr("b", 20, 1, 0.01, 0.24)], target=tid)
    body = _compare(v2, cand, base).json()
    assert body["status"] == "pass"
    assert {d["technique"]: d["status"] for d in body["diffs"]} == {"a": "unchanged", "b": "improved"}


def test_compare_inconclusive_with_few_trials(v2):
    tid = v2.target("a")
    base = _seed(v2, [_tr("prompt_injection", 2, 0, 0.0, 0.66)], target=tid)
    cand = _seed(v2, [_tr("prompt_injection", 2, 2, 0.34, 1.0)], target=tid)
    body = _compare(v2, cand, base).json()
    assert body["status"] == "inconclusive"
    assert body["diffs"][0]["status"] == "inconclusive"


def test_compare_org_isolation(v2):
    mine = _seed(v2, [_tr("t", 20, 1, 0.01, 0.24)], org="a")
    other = _seed(v2, [_tr("t", 20, 1, 0.01, 0.24)], org="b")
    assert _compare(v2, mine, other).status_code == 404  # baseline in another org
    assert _compare(v2, other, mine).status_code == 404  # candidate in another org
    assert _compare(v2, mine, "c-does-not-exist").status_code == 404
    assert _compare(v2, mine, other, "admin", "b").status_code == 404
    assert _compare(v2, mine, mine).status_code == 200


def test_compare_is_a_pure_read(v2):
    tid = v2.target("a")
    base = _seed(v2, [_tr("t", 20, 1, 0.01, 0.24)], target=tid)
    cand = _seed(v2, [_tr("t", 20, 1, 0.01, 0.24)], target=tid)
    assert _compare(v2, cand, base).status_code == 200
    assert v2.queue.enqueued == []
    assert len(CampaignRepo(v2.factory).list_for_target(tid)) == 2
