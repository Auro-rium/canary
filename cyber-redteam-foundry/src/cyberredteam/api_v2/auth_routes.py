"""/api/v2/auth/* and /api/v2/me (WP8).

Browser login is OIDC authorization code + PKCE. The callback sets two cookies:

* ``canary_session``: HttpOnly, SameSite=Lax, Secure (unless disabled for local
  http dev). Only its hash is stored server-side.
* ``canary_csrf``: readable by the page (double submit). Send it back as
  ``X-CSRF-Token`` on POST/PUT/PATCH/DELETE; it is checked against the hash
  bound to the session.

The browser never holds an API token: the Vercel proxy forwards these cookies
and injects nothing. API keys are for CI and are created only from a browser
session (an API key cannot mint further keys) or the ``cyber-rt auth`` CLI.
"""

from __future__ import annotations

import logging
import secrets
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse

from cyberredteam.api_v2.schemas import (
    ApiKeyCreate,
    ApiKeyCreated,
    ApiKeyList,
    ApiKeyView,
    Me,
    ProvidersView,
)
from cyberredteam.auth.deps import SESSION_COOKIE, get_auth_repo, get_principal
from cyberredteam.auth.oidc import OIDCError, OIDCProvider, configured_providers, new_pkce
from cyberredteam.auth.principal import Principal
from cyberredteam.auth.repo import AuthError, AuthRepo
from cyberredteam.auth.tokens import token_matches
from cyberredteam.settings import get_settings
from cyberredteam.storage.v2.repositories import AuditRepo

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v2", tags=["auth"])

CSRF_COOKIE = "canary_csrf"


def get_oidc_providers() -> dict[str, OIDCProvider]:
    return configured_providers(get_settings())


def _provider(name: str, providers: dict[str, OIDCProvider]) -> OIDCProvider:
    provider = providers.get(name)
    if provider is None:
        raise HTTPException(status_code=404, detail="Unknown login provider")
    return provider


def _safe_next(value: str | None) -> str:
    """Only same-site relative paths (no open redirect)."""
    if not value or not value.startswith("/") or value.startswith("//") or "\\" in value:
        return "/"
    parts = urlsplit(value)
    if parts.scheme or parts.netloc:
        return "/"
    return value[:500]


def _redirect_uri(request: Request, provider: str) -> str:
    base = get_settings().public_base_url or str(request.base_url)
    return f"{base.rstrip('/')}/api/v2/auth/callback/{provider}"


@router.get("/auth/providers", response_model=ProvidersView)
def list_providers(providers: dict[str, OIDCProvider] = Depends(get_oidc_providers)):
    """Public: which login buttons to show."""
    return ProvidersView(providers=sorted(providers))


@router.get("/auth/login/{provider}", status_code=302, response_class=RedirectResponse)
def login(
    provider: str,
    request: Request,
    next: str | None = None,
    providers: dict[str, OIDCProvider] = Depends(get_oidc_providers),
    repo: AuthRepo = Depends(get_auth_repo),
):
    """Public: start an OIDC login (redirects to the identity provider)."""
    idp = _provider(provider, providers)
    state = secrets.token_urlsafe(32)
    verifier, challenge = new_pkce()
    repo.save_login_state(state, provider, verifier, _safe_next(next))
    url = idp.authorization_url(state=state, code_challenge=challenge,
                                redirect_uri=_redirect_uri(request, provider))
    return RedirectResponse(url, status_code=302)


@router.get("/auth/callback/{provider}", status_code=302, response_class=RedirectResponse)
async def callback(
    provider: str,
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    providers: dict[str, OIDCProvider] = Depends(get_oidc_providers),
    repo: AuthRepo = Depends(get_auth_repo),
):
    """Public: OIDC redirect target. Sets the session and CSRF cookies."""
    idp = _provider(provider, providers)
    pending = repo.consume_login_state(state or "")
    if pending is None or pending.provider != provider:
        raise HTTPException(status_code=400, detail="Invalid or expired login state")
    if error or not code:
        raise HTTPException(status_code=400, detail="Login was not completed")
    try:
        identity = await idp.exchange(code=code, code_verifier=pending.code_verifier,
                                      redirect_uri=_redirect_uri(request, provider))
        if identity.provider != provider:
            raise OIDCError("provider mismatch")
        user_id = repo.resolve_oidc_user(provider, identity.subject, identity.email,
                                         identity.email_verified)
    except OIDCError:
        raise HTTPException(status_code=400, detail="Login with the identity provider failed") from None
    except AuthError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from None

    settings = get_settings()
    token, csrf = repo.create_session(user_id, settings.session_ttl_s)
    AuditRepo(repo.factory).record(f"user:{user_id}", "auth.login", f"user:{user_id}",
                                    {"provider": provider})
    response = RedirectResponse(pending.redirect_to, status_code=302)
    common = {"max_age": settings.session_ttl_s, "secure": settings.session_cookie_secure, "path": "/"}
    response.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="lax", **common)
    response.set_cookie(CSRF_COOKIE, csrf, httponly=False, samesite="strict", **common)
    return response


@router.post("/auth/logout")
def logout(principal: Principal = Depends(get_principal), repo: AuthRepo = Depends(get_auth_repo)):
    if principal.session_hash:
        repo.revoke_session(principal.session_hash)
    response = JSONResponse({"status": "logged_out"})
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")
    return response


@router.get("/me", response_model=Me)
def me(request: Request, principal: Principal = Depends(get_principal)):
    csrf = request.cookies.get(CSRF_COOKIE)
    return Me(
        user_id=principal.user_id, org_id=principal.org_id, email=principal.email,
        display_name=principal.display_name, role=principal.role,
        permissions=sorted(principal.permissions), auth_method=principal.auth_method,
        csrf_token=csrf if token_matches(csrf, principal.csrf_hash) else None,
    )


def _key_view(k) -> ApiKeyView:
    return ApiKeyView(key_id=k.key_id, name=k.name, created_at=k.created_at,
                      expires_at=k.expires_at, last_used_at=k.last_used_at, revoked_at=k.revoked_at)


@router.post("/auth/api-keys", status_code=201, response_model=ApiKeyCreated)
def create_api_key(
    body: ApiKeyCreate,
    principal: Principal = Depends(get_principal),
    repo: AuthRepo = Depends(get_auth_repo),
):
    """Create a CI key for yourself (it acts with your role). Browser sessions only."""
    if principal.auth_method != "session":
        raise HTTPException(status_code=403, detail="API keys can only be created from a browser session")
    key_id, full = repo.create_api_key(principal.user_id, body.name, body.expires_in_days)
    AuditRepo(repo.factory).record(principal.actor, "api_key.create", f"api_key:{key_id}")
    key = next(k for k in repo.list_api_keys(principal.user_id) if k.key_id == key_id)
    return ApiKeyCreated(key=_key_view(key), api_key=full)


@router.get("/auth/api-keys", response_model=ApiKeyList)
def list_api_keys(principal: Principal = Depends(get_principal), repo: AuthRepo = Depends(get_auth_repo)):
    return ApiKeyList(items=[_key_view(k) for k in repo.list_api_keys(principal.user_id)])


@router.delete("/auth/api-keys/{key_id}")
def revoke_api_key(
    key_id: str,
    principal: Principal = Depends(get_principal),
    repo: AuthRepo = Depends(get_auth_repo),
) -> dict[str, str]:
    if not repo.revoke_api_key(principal.user_id, key_id):
        raise HTTPException(status_code=404, detail="API key not found")
    AuditRepo(repo.factory).record(principal.actor, "api_key.revoke", f"api_key:{key_id}")
    return {"key_id": key_id, "status": "revoked"}
