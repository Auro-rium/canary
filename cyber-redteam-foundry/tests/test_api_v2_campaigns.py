"""/api/v2/campaigns create/list/get (WP8): the launch gate, production limits,
kill switch, enqueue failure, paging and org isolation."""

from __future__ import annotations

import pytest

from cyberredteam.api import app
from cyberredteam.api_v2.deps import get_job_queue
from cyberredteam.jobs.control import ControlStore
from cyberredteam.storage.v2.repositories import AuditRepo, BudgetLedgerRepo, CampaignRepo

SAFE_PROD = {
    "techniques": ["prompt_injection"], "trials_per_technique": 2, "max_turns": 3,
    "rate_limit_rps": 1.0, "max_parallel_conversations": 2, "max_total_requests": 300,
}


def launch(v2, target_id, policy=None, role="operator", org="a"):
    body = {"target_id": target_id, "policy": policy or {"techniques": ["prompt_injection"]}}
    return v2.client.post("/api/v2/campaigns", json=body, headers=v2.h(role, org))


def test_operator_launches_against_verified_target(v2):
    tid = v2.target()
    resp = launch(v2, tid)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    cid = body["campaign_id"]
    assert body["status"] == "queued" and body["target_id"] == tid
    assert body["created_by"] == v2.actor("operator").actor
    assert v2.queue.enqueued == [cid]
    assert CampaignRepo(v2.factory).get(cid).created_by == v2.actor("operator").actor
    assert [e.object for e in AuditRepo(v2.factory).list(action="campaign.create")] == [f"campaign:{cid}"]
    assert "tok-TARGET" not in resp.text


def test_unverified_target_is_403_and_nothing_queued(v2):
    tid = v2.target(verified=False)
    assert launch(v2, tid).status_code == 403
    assert v2.queue.enqueued == [] and CampaignRepo(v2.factory).list_for_target(tid) == []


@pytest.mark.parametrize("override", [
    {"rate_limit_rps": 2.0},
    {"max_parallel_conversations": 3},
    {"max_total_requests": 301},
    {"allow_destructive_tools": True},
    {"techniques": ["workflow_manipulation"]},
])
def test_production_limits_are_rejected_not_clamped(v2, override):
    tid = v2.target(environment="production")
    resp = launch(v2, tid, {**SAFE_PROD, **override})
    assert resp.status_code == 422, resp.text
    assert v2.queue.enqueued == [] and CampaignRepo(v2.factory).list_for_target(tid) == []


def test_production_default_policy_is_rejected_and_limits_accepted(v2):
    tid = v2.target(environment="production")
    assert launch(v2, tid).status_code == 422  # default parallel=4, total=500
    resp = launch(v2, tid, SAFE_PROD)
    assert resp.status_code == 201, resp.text
    assert resp.json()["policy"]["rate_limit_rps"] == 1.0  # stored as given, not altered


def test_staging_allows_higher_limits(v2):
    tid = v2.target(environment="staging")
    assert launch(v2, tid, {**SAFE_PROD, "max_parallel_conversations": 8, "rate_limit_rps": 5}
                  ).status_code == 201


def test_kill_switch_blocks_launches(v2, monkeypatch):
    tid = v2.target()
    ControlStore(v2.factory).set_kill_switch(True, "test")
    assert launch(v2, tid).status_code == 409
    ControlStore(v2.factory).set_kill_switch(False, "test")
    monkeypatch.setenv("CANARY_KILL_SWITCH", "1")
    assert launch(v2, tid).status_code == 409
    assert v2.queue.enqueued == []


def test_enqueue_failure_marks_campaign_failed(v2):
    class Broken:
        async def enqueue_campaign(self, campaign_id):
            raise ConnectionError("db down")

    app.dependency_overrides[get_job_queue] = lambda: Broken()
    tid = v2.target()
    assert launch(v2, tid).status_code == 503
    (rec,) = CampaignRepo(v2.factory).list_for_target(tid)
    assert rec.status == "failed"


def test_allowlist_narrows(v2, monkeypatch):
    tid = v2.target()
    monkeypatch.setenv("ALLOWED_TARGETS", "some-other-target")
    assert launch(v2, tid).status_code == 403
    monkeypatch.setenv("ALLOWED_TARGETS", tid)
    assert launch(v2, tid).status_code == 201


def test_unknown_policy_fields_rejected(v2):
    resp = launch(v2, v2.target(), {"techniques": ["prompt_injection"], "rate_limit": 9})
    assert resp.status_code == 422


def test_list_is_paged_with_total_and_org_scoped(v2):
    tid = v2.target()
    ids = [v2.campaign(tid) for _ in range(5)]
    v2.campaign(v2.target("b"))
    page = v2.client.get("/api/v2/campaigns?page=1&page_size=2", headers=v2.h("viewer")).json()
    assert page["total"] == 5 and len(page["items"]) == 2 and page["page_size"] == 2
    page3 = v2.client.get("/api/v2/campaigns?page=3&page_size=2", headers=v2.h("viewer")).json()
    assert len(page3["items"]) == 1
    seen = {i["campaign_id"] for p in (1, 2, 3)
            for i in v2.client.get(f"/api/v2/campaigns?page={p}&page_size=2", headers=v2.h("viewer")
                                   ).json()["items"]}
    assert seen == set(ids)
    other = v2.client.get("/api/v2/campaigns", headers=v2.h("viewer", "b")).json()
    assert other["total"] == 1 and not ({i["campaign_id"] for i in other["items"]} & set(ids))
    filtered = v2.client.get(f"/api/v2/campaigns?status=queued&target_id={tid}", headers=v2.h("viewer"))
    assert filtered.json()["total"] == 5
    assert v2.client.get("/api/v2/campaigns?page_size=1000", headers=v2.h("viewer")).status_code == 422


def test_detail_has_conversations_results_budget_and_last_seq(v2):
    chain = v2.chain()
    cid = chain["campaign_id"]
    BudgetLedgerRepo(v2.factory).add(cid, "requests", 3)
    detail = v2.client.get(f"/api/v2/campaigns/{cid}", headers=v2.h("viewer")).json()
    assert detail["confirmed"] == 1 and detail["total_conversations"] == 1
    (conv,) = detail["conversations"]
    assert conv["conversation_id"] == chain["conversation_id"]
    assert conv["verdict"] == "confirmed" and conv["turns"] == 1
    assert detail["budget"]["requests_used"] == 3
    assert detail["last_seq"] == 0 and detail["target_name"] == "agent-a"
    assert v2.client.get(f"/api/v2/campaigns/{cid}", headers=v2.h("admin", "b")).status_code == 404


def test_events_stream_closes_when_credential_is_revoked(v2, monkeypatch):
    """The SSE stream re-validates its credential and ends once it is revoked."""
    from cyberredteam.auth.repo import AuthRepo
    from cyberredteam.jobs import api_v2 as control

    monkeypatch.setattr(control, "REVALIDATE_S", 0.0)
    monkeypatch.setenv("SSE_POLL_INTERVAL_S", "0.05")
    cid = v2.campaign(v2.target("a"), status="running")
    viewer = v2.actor("viewer")
    real = AuthRepo.is_still_valid
    seen = []

    def revoke_then_check(self, principal):
        if not seen:
            self.revoke_api_key(viewer.user_id, principal.api_key_id)  # revoked mid-stream
        seen.append(real(self, principal))
        return seen[-1]

    monkeypatch.setattr(AuthRepo, "is_still_valid", revoke_then_check)
    with v2.client.stream("GET", f"/api/v2/campaigns/{cid}/events", headers=viewer.headers("api_key")) as r:
        assert r.status_code == 200
        body = "".join(r.iter_text())
    assert seen == [False] and "session ended" in body


def test_is_still_valid_tracks_session_and_user_state(v2):
    op = v2.actor("operator")
    principal = v2.auth.authenticate_session(op.session)
    assert v2.auth.is_still_valid(principal)
    v2.auth.set_disabled(op.user_id, True)
    assert not v2.auth.is_still_valid(principal)
