"""WP8 done-when: every /api/v2 route x every role, including cross-org access.

For each route, with both credential types (CI API key and browser session):

* anonymous -> 401 (public routes excepted);
* each role of org A -> the route's success code if the role is high enough, else 403;
* admin of org B on org A's object -> 404 (indistinguishable from missing);
  on a list route -> 200 without any of org A's ids.

``test_matrix_covers_every_v2_route`` fails when a route is added without an entry.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

import pytest
from api_v2_support import ENDPOINT

from cyberredteam.api import app

RANK = {"viewer": 0, "operator": 1, "admin": 2}


@dataclass
class Route:
    method: str
    path: str
    min_role: str | None  # None = public
    scope: str  # object | list | global | self | public
    build: Callable  # (env, owner_actor, mode) -> (url, kwargs, marker_id or None)
    ok: int = 200
    platform: bool = False  # also needs CANARY_PLATFORM_ADMINS (only org A's admin is listed)


def _target_body():
    return {
        "name": "t", "endpoint": ENDPOINT, "auth": {"type": "bearer", "token": "tok-NEW-secret-1"},
        "request_template": '{"input": "{{MESSAGE}}"}', "response_path": "reply",
        "session_mode": "stateless_history", "environment": "staging",
    }


def _url(u, marker=None, **kw):
    return u, kw, marker


def _logout(env, actor, mode):
    session, csrf = env.auth.create_session(actor.user_id, 600)
    if mode == "session":
        from cyberredteam.api_v2.auth_routes import CSRF_COOKIE
        from cyberredteam.auth.deps import SESSION_COOKIE

        headers = {"Cookie": f"{SESSION_COOKIE}={session}; {CSRF_COOKIE}={csrf}", "X-CSRF-Token": csrf}
        return "/api/v2/auth/logout", {"headers": headers}, None
    return "/api/v2/auth/logout", {}, None


def _own_key(env, actor, mode):
    key_id, _ = env.auth.create_api_key(actor.user_id, "tmp")
    return f"/api/v2/auth/api-keys/{key_id}", {}, None


def _new_campaign(env, actor, mode):
    tid = env.target(actor.org)
    return "/api/v2/campaigns", {"json": {"target_id": tid, "policy": {
        "techniques": ["prompt_injection"], "trials_per_technique": 1, "max_turns": 2}}}, None


ROUTES = [
    Route("GET", "/api/v2/auth/providers", None, "public", lambda e, a, m: _url("/api/v2/auth/providers")),
    Route("GET", "/api/v2/auth/login/{provider}", None, "public",
          lambda e, a, m: _url("/api/v2/auth/login/fake?next=/x"), ok=302),
    Route("GET", "/api/v2/auth/callback/{provider}", None, "public",
          lambda e, a, m: _url("/api/v2/auth/callback/fake?code=c&state=s"), ok=400),
    Route("GET", "/api/v2/me", "viewer", "global", lambda e, a, m: _url("/api/v2/me")),
    Route("POST", "/api/v2/auth/logout", "viewer", "global", _logout),
    Route("GET", "/api/v2/auth/api-keys", "viewer", "global", lambda e, a, m: _url("/api/v2/auth/api-keys")),
    Route("POST", "/api/v2/auth/api-keys", "viewer", "global",
          lambda e, a, m: _url("/api/v2/auth/api-keys", json={"name": "ci"}), ok=201),
    Route("DELETE", "/api/v2/auth/api-keys/{key_id}", "viewer", "self", _own_key),
    Route("GET", "/api/v2/targets", "viewer", "list",
          lambda e, a, m: (lambda t: _url("/api/v2/targets", t))(e.target(a.org))),
    Route("POST", "/api/v2/targets", "operator", "global",
          lambda e, a, m: _url("/api/v2/targets", json=_target_body()), ok=201),
    Route("GET", "/api/v2/targets/{target_id}", "viewer", "object",
          lambda e, a, m: _url(f"/api/v2/targets/{e.target(a.org)}")),
    Route("PATCH", "/api/v2/targets/{target_id}", "operator", "object",
          lambda e, a, m: _url(f"/api/v2/targets/{e.target(a.org)}", json={"name": "renamed"})),
    Route("DELETE", "/api/v2/targets/{target_id}", "operator", "object",
          lambda e, a, m: _url(f"/api/v2/targets/{e.target(a.org)}")),
    Route("POST", "/api/v2/targets/{target_id}/verify", "operator", "object",
          lambda e, a, m: _url(f"/api/v2/targets/{e.target(a.org, verified=False)}/verify",
                               json={"method": "response_header"})),
    Route("POST", "/api/v2/targets/{target_id}/test-connection", "operator", "object",
          lambda e, a, m: _url(f"/api/v2/targets/{e.target(a.org, verified=False)}/test-connection")),
    Route("GET", "/api/v2/campaigns", "viewer", "list",
          lambda e, a, m: (lambda c: _url("/api/v2/campaigns", c))(e.campaign(e.target(a.org)))),
    Route("POST", "/api/v2/campaigns", "operator", "object", _new_campaign, ok=201),
    Route("GET", "/api/v2/campaigns/{campaign_id}", "viewer", "object",
          lambda e, a, m: _url(f"/api/v2/campaigns/{e.campaign(e.target(a.org))}")),
    Route("GET", "/api/v2/campaigns/{campaign_id}/compare", "viewer", "object",
          lambda e, a, m: (lambda t: _url(
              f"/api/v2/campaigns/{e.campaign(t, status='completed')}/compare"
              f"?baseline={e.campaign(t, status='completed')}"))(e.target(a.org))),
    Route("POST", "/api/v2/campaigns/{campaign_id}/cancel", "operator", "object",
          lambda e, a, m: _url(f"/api/v2/campaigns/{e.campaign(e.target(a.org), status='running')}/cancel")),
    Route("GET", "/api/v2/campaigns/{campaign_id}/events", "viewer", "object",
          lambda e, a, m: _url(f"/api/v2/campaigns/{e.campaign(e.target(a.org), status='completed')}/events")),
    Route("GET", "/api/v2/admin/kill-switch", "viewer", "global",
          lambda e, a, m: _url("/api/v2/admin/kill-switch")),
    Route("POST", "/api/v2/admin/kill-switch", "admin", "global",
          lambda e, a, m: _url("/api/v2/admin/kill-switch", json={"enabled": False}),
          platform=True),
    Route("GET", "/api/v2/conversations/{conversation_id}", "viewer", "object",
          lambda e, a, m: _url(f"/api/v2/conversations/{e.chain(a.org)['conversation_id']}")),
    Route("GET", "/api/v2/findings", "viewer", "list",
          lambda e, a, m: (lambda c: _url("/api/v2/findings", c["finding_id"]))(e.chain(a.org))),
    Route("GET", "/api/v2/findings/{finding_id}", "viewer", "object",
          lambda e, a, m: _url(f"/api/v2/findings/{e.chain(a.org)['finding_id']}")),
    Route("PUT", "/api/v2/findings/{finding_id}/status", "operator", "object",
          lambda e, a, m: _url(f"/api/v2/findings/{e.chain(a.org)['finding_id']}/status",
                               json={"status": "needs_review"})),
    Route("GET", "/api/v2/reports/{campaign_id}", "viewer", "object",
          lambda e, a, m: _url(f"/api/v2/reports/{e.chain(a.org)['campaign_id']}")),
]


def test_matrix_covers_every_v2_route():
    # Every v2 router keeps include_in_schema, so the OpenAPI document lists them all.
    declared = {
        (method.upper(), path)
        for path, ops in app.openapi()["paths"].items()
        if path.startswith("/api/v2")
        for method in ops
    }
    assert declared == {(r.method, r.path) for r in ROUTES}


def _call(env, route: Route, owner, headers: dict, mode: str):
    url, kwargs, marker = route.build(env, owner, mode)
    extra = kwargs.pop("headers", {})
    hdrs = {**headers, **extra} if headers else {}  # anonymous calls send no credentials
    resp = env.client.request(route.method, url, headers=hdrs, follow_redirects=False, **kwargs)
    return resp, marker


def _expected_ok(route: Route, mode: str) -> int:
    if route.path == "/api/v2/auth/api-keys" and route.method == "POST" and mode == "api_key":
        return 403  # an API key cannot mint further keys
    return route.ok


@pytest.mark.parametrize("mode", ["api_key", "session"])
@pytest.mark.parametrize("route", ROUTES, ids=lambda r: f"{r.method} {r.path}")
def test_role_matrix(v2, route, mode, monkeypatch):
    monkeypatch.setenv("CANARY_PLATFORM_ADMINS", "admin@a.example")
    env = v2
    viewer_a = env.actor("viewer", "a")
    # anonymous
    resp, _ = _call(env, route, viewer_a, {}, mode)
    if route.min_role is None:
        assert resp.status_code == route.ok, resp.text
        return
    assert resp.status_code == 401, (route.path, resp.status_code, resp.text)

    # every role of the owning org
    for role in RANK:
        actor = env.actor(role, "a")
        resp, _ = _call(env, route, actor, actor.headers(mode), mode)
        if RANK[role] >= RANK[route.min_role]:
            assert resp.status_code == _expected_ok(route, mode), (role, mode, resp.text)
        else:
            assert resp.status_code == 403, (role, mode, resp.status_code, resp.text)

    # cross-org: org B's admin against org A's objects
    other = env.actor("admin", "b")
    resp, marker = _call(env, route, viewer_a, other.headers(mode), mode)
    if route.scope in ("object", "self"):
        assert resp.status_code == 404, (mode, resp.status_code, resp.text)
    elif route.scope == "list":
        assert resp.status_code == 200
        assert marker and marker not in resp.text
        assert resp.json()["items"] == [] or all(marker not in str(i) for i in resp.json()["items"])
    elif route.platform:  # org B's admin is not a platform admin
        assert resp.status_code == 403, (mode, resp.status_code, resp.text)
    else:  # global: acts on B's own data
        assert resp.status_code == _expected_ok(route, mode), resp.text


def test_wrong_role_writes_nothing(v2):
    """A refused (403) or cross-org (404) launch leaves no campaign row and no enqueue."""
    tid = v2.target("a")
    body = {"target_id": tid, "policy": {"techniques": ["prompt_injection"]}}
    assert v2.client.post("/api/v2/campaigns", json=body, headers=v2.h("viewer")).status_code == 403
    assert v2.client.post("/api/v2/campaigns", json=body, headers=v2.h("admin", "b")).status_code == 404
    assert v2.queue.enqueued == []
    from cyberredteam.storage.v2.repositories import CampaignRepo

    assert CampaignRepo(v2.factory).list_for_target(tid) == []


def test_org_admin_is_not_a_platform_admin(v2, monkeypatch):
    monkeypatch.setenv("CANARY_PLATFORM_ADMINS", "")
    resp = v2.client.post("/api/v2/admin/kill-switch", json={"enabled": True}, headers=v2.h("admin"))
    assert resp.status_code == 403
    assert v2.client.get("/api/v2/admin/kill-switch", headers=v2.h("admin")).json()["enabled"] is False
    # by user id works too
    monkeypatch.setenv("CANARY_PLATFORM_ADMINS", v2.actor("admin").user_id)
    assert v2.client.post("/api/v2/admin/kill-switch", json={"enabled": False},
                          headers=v2.h("admin")).status_code == 200
    assert v2.client.post("/api/v2/admin/kill-switch", json={"enabled": False},
                          headers=v2.h("operator")).status_code == 403
