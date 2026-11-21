"""WP8 OIDC login (authorization code + PKCE + one-time state) with FakeOIDCProvider.

No real identity provider is contacted. Users created by the ``v2`` fixture are
invitations (email set, subject unset) until their first login binds them.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

from cyberredteam.auth.oidc import OIDCIdentity
from cyberredteam.auth.tables import AuthSessionRow, UserRow
from cyberredteam.storage.v2.db import session_scope
from cyberredteam.storage.v2.repositories import AuditRepo


def _start(v2, next_path="/campaigns"):
    resp = v2.client.get(f"/api/v2/auth/login/fake?next={next_path}", follow_redirects=False)
    assert resp.status_code == 302
    loc = urlsplit(resp.headers["location"])
    assert loc.netloc == "idp.invalid"
    q = parse_qs(loc.query)
    assert q["redirect_uri"] == ["https://testserver/api/v2/auth/callback/fake"]
    return q["state"][0]


def _identity(email="operator@a.example", subject="sub-123", verified=True):
    return OIDCIdentity(provider="fake", subject=subject, email=email, email_verified=verified,
                        name="Op")


def _finish(v2, state, identity):
    code = v2.oidc.issue(identity, state)
    return v2.client.get(f"/api/v2/auth/callback/fake?code={code}&state={state}",
                         follow_redirects=False)


def _sessions(v2) -> int:
    with session_scope(v2.factory) as s:
        return len(s.query(AuthSessionRow).all())


def test_providers_list_is_public(v2):
    assert v2.client.get("/api/v2/auth/providers").json() == {"providers": ["fake"]}


def test_login_binds_invite_and_sets_secure_cookies(v2):
    state = _start(v2)
    resp = _finish(v2, state, _identity())
    assert resp.status_code == 302 and resp.headers["location"] == "/campaigns"
    cookies = resp.headers.get_list("set-cookie")
    session_cookie = next(c for c in cookies if c.startswith("canary_session="))
    csrf_cookie = next(c for c in cookies if c.startswith("canary_csrf="))
    lowered = session_cookie.lower()
    assert "httponly" in lowered and "secure" in lowered and "samesite=lax" in lowered
    assert "httponly" not in csrf_cookie.lower()

    me = v2.client.get("/api/v2/me").json()  # cookie jar
    operator = v2.actor("operator")
    assert me["user_id"] == operator.user_id and me["auth_method"] == "session"
    csrf = v2.client.cookies.get("canary_csrf")
    assert me["csrf_token"] == csrf
    # the session works for an unsafe call only with the CSRF header
    tid = v2.target()
    assert v2.client.patch(f"/api/v2/targets/{tid}", json={"name": "n"}).status_code == 403
    ok = v2.client.patch(f"/api/v2/targets/{tid}", json={"name": "n"}, headers={"X-CSRF-Token": csrf})
    assert ok.status_code == 200
    with session_scope(v2.factory) as s:
        row = s.get(UserRow, operator.user_id)
        assert (row.oidc_provider, row.oidc_subject) == ("fake", "sub-123")
    assert AuditRepo(v2.factory).list(action="auth.login")[0].actor == operator.actor


def test_identity_is_the_subject_not_the_email(v2):
    _finish(v2, _start(v2), _identity())
    v2.client.cookies.clear()
    # same subject, different email: still the same user
    assert _finish(v2, _start(v2), _identity(email="renamed@elsewhere.example")).status_code == 302
    assert v2.client.get("/api/v2/me").json()["user_id"] == v2.actor("operator").user_id
    v2.client.cookies.clear()
    # someone else presenting the bound email with another subject gets nothing
    resp = _finish(v2, _start(v2), _identity(subject="attacker-sub"))
    assert resp.status_code == 403


def test_uninvited_and_unverified_identities_are_refused(v2):
    before = _sessions(v2)
    assert _finish(v2, _start(v2), _identity(email="stranger@x.example")).status_code == 403
    assert _finish(v2, _start(v2), _identity(verified=False)).status_code == 403
    assert _finish(v2, _start(v2), _identity(email=None)).status_code == 403
    assert _sessions(v2) == before
    assert v2.client.get("/api/v2/me").status_code == 401


def test_invite_restricted_to_another_provider(v2):
    v2.auth.create_user(v2.orgs["a"], "viewer", email="gh-only@a.example", oidc_provider="github")
    assert _finish(v2, _start(v2), _identity(email="gh-only@a.example", subject="s9")).status_code == 403


def test_disabled_user_cannot_log_in(v2):
    v2.auth.set_disabled(v2.actor("operator").user_id, True)
    assert _finish(v2, _start(v2), _identity()).status_code == 403


def test_state_is_one_time_and_bound_to_provider(v2):
    state = _start(v2)
    code = v2.oidc.issue(_identity(), state)
    first = v2.client.get(f"/api/v2/auth/callback/fake?code={code}&state={state}", follow_redirects=False)
    assert first.status_code == 302
    replay = v2.client.get(f"/api/v2/auth/callback/fake?code={code}&state={state}", follow_redirects=False)
    assert replay.status_code == 400
    assert v2.client.get("/api/v2/auth/callback/fake?code=x&state=forged").status_code == 400
    assert v2.client.get("/api/v2/auth/callback/nope?code=x&state=y").status_code == 404
    assert v2.client.get("/api/v2/auth/login/nope", follow_redirects=False).status_code == 404


def test_idp_error_consumes_state(v2):
    state = _start(v2)
    assert v2.client.get(f"/api/v2/auth/callback/fake?error=access_denied&state={state}").status_code == 400
    code = v2.oidc.issue(_identity(), state)
    assert v2.client.get(f"/api/v2/auth/callback/fake?code={code}&state={state}").status_code == 400


def test_no_open_redirect(v2):
    for evil in ("//evil.example/x", "https://evil.example/", "/\\evil.example"):
        state = _start(v2, next_path=evil)
        resp = _finish(v2, state, _identity())
        assert resp.headers["location"] == "/"
        v2.client.cookies.clear()


def test_logout_revokes_the_session(v2):
    _finish(v2, _start(v2), _identity())
    csrf = v2.client.cookies.get("canary_csrf")
    assert v2.client.post("/api/v2/auth/logout", headers={"X-CSRF-Token": csrf}).status_code == 200
    assert v2.client.get("/api/v2/me").status_code == 401


# ── login CSRF: the callback must come from the browser that started the login ──

def _fresh_client(v2):
    from fastapi.testclient import TestClient

    from cyberredteam.api import app

    return TestClient(app, base_url="https://testserver")


def test_login_sets_scoped_state_cookie(v2):
    resp = v2.client.get("/api/v2/auth/login/fake", follow_redirects=False)
    cookie = next(c for c in resp.headers.get_list("set-cookie") if c.startswith("canary_oidc_state="))
    low = cookie.lower()
    assert "httponly" in low and "secure" in low and "samesite=lax" in low
    assert "path=/api/v2/auth/callback" in low and "max-age=600" in low


def test_callback_without_state_cookie_is_refused(v2):
    state = _start(v2)
    code = v2.oidc.issue(_identity(), state)
    v2.client.cookies.clear()  # attacker-supplied link opened in a different browser
    resp = v2.client.get(f"/api/v2/auth/callback/fake?code={code}&state={state}", follow_redirects=False)
    assert resp.status_code == 400
    assert _sessions(v2) == len(v2.actors)  # no session was minted (fixture sessions only)
    assert "canary_session" not in "".join(resp.headers.get_list("set-cookie"))


def test_callback_with_wrong_state_cookie_is_refused(v2):
    state = _start(v2)
    code = v2.oidc.issue(_identity(), state)
    v2.client.cookies.clear()
    v2.client.cookies.set("canary_oidc_state", "not-the-binder", path="/api/v2/auth/callback")
    resp = v2.client.get(f"/api/v2/auth/callback/fake?code={code}&state={state}", follow_redirects=False)
    assert resp.status_code == 400
    assert _sessions(v2) == len(v2.actors)
    assert v2.client.get("/api/v2/me").status_code == 401


def test_state_cookie_is_deleted_after_callback(v2):
    resp = _finish(v2, _start(v2), _identity())
    assert resp.status_code == 302
    cookies = resp.headers.get_list("set-cookie")
    gone = next(c for c in cookies if c.startswith("canary_oidc_state="))
    assert "max-age=0" in gone.lower() or "1970" in gone


def test_oidc_login_refused_in_production_without_public_base_url(v2, monkeypatch):
    monkeypatch.setenv("CANARY_ENV", "production")
    monkeypatch.delenv("PUBLIC_BASE_URL", raising=False)
    resp = v2.client.get("/api/v2/auth/login/fake", follow_redirects=False)
    assert resp.status_code == 503
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://app.example")
    resp = v2.client.get("/api/v2/auth/login/fake", follow_redirects=False)
    assert resp.status_code == 302
    assert "redirect_uri=https%3A%2F%2Fapp.example%2Fapi%2Fv2%2Fauth%2Fcallback%2Ffake" in resp.headers["location"]


def test_insecure_session_cookies_refused_in_production(v2, monkeypatch):
    monkeypatch.setenv("CANARY_ENV", "production")
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://app.example")
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")
    assert v2.client.get("/api/v2/auth/login/fake", follow_redirects=False).status_code == 503
    monkeypatch.setenv("CANARY_ENV", "dev")
    assert v2.client.get("/api/v2/auth/login/fake", follow_redirects=False).status_code == 302
