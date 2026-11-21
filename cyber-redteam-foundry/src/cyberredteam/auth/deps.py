"""FastAPI dependencies for authentication and authorization (WP8).

* ``require_auth`` is installed app-wide: every route needs a principal unless
  its path is in the small public allowlist (health, OIDC login/callback,
  provider list). A new route is therefore authenticated by default.
* Credentials: a CI API key (``Authorization: Bearer cnry_...`` or
  ``X-API-Key``) or the browser session cookie set by the OIDC callback. A
  presented-but-invalid credential is a 401; there is no fallback to another
  credential and no shared master token.
* Cookie sessions must send ``X-CSRF-Token`` on unsafe methods.
* ``require(permission)`` gives 403 when the role lacks the permission. Org
  isolation is enforced in each query (another org's object is a 404).
"""

from __future__ import annotations

from collections.abc import Callable

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session, sessionmaker

from cyberredteam.auth.principal import Principal
from cyberredteam.auth.repo import AuthRepo
from cyberredteam.auth.tokens import token_matches
from cyberredteam.storage.v2.db import make_session_factory

SESSION_COOKIE = "canary_session"
CSRF_HEADER = "X-CSRF-Token"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

PUBLIC_PATHS = frozenset({"/health", "/api/v2/auth/providers"})
PUBLIC_PREFIXES = ("/api/v2/auth/login/", "/api/v2/auth/callback/")

_factory: sessionmaker[Session] | None = None


def get_db_factory() -> sessionmaker[Session]:
    """The v2 database for every API v2 route (tests override this one dependency)."""
    global _factory
    if _factory is None:
        _factory = make_session_factory()
    return _factory


def get_auth_repo(factory: sessionmaker[Session] = Depends(get_db_factory)) -> AuthRepo:
    return AuthRepo(factory)


def is_public_path(path: str) -> bool:
    return path in PUBLIC_PATHS or path.startswith(PUBLIC_PREFIXES)


def _unauthorized(detail: str = "Authentication required") -> HTTPException:
    return HTTPException(status_code=401, detail=detail, headers={"WWW-Authenticate": "Bearer"})


def authenticate(request: Request, repo: AuthRepo) -> Principal:
    authz = request.headers.get("authorization")
    header_key = request.headers.get("x-api-key")
    if authz is not None or header_key is not None:
        presented = header_key
        if authz is not None:
            scheme, _, value = authz.partition(" ")
            if scheme.lower() != "bearer" or not value.strip():
                raise _unauthorized("Invalid credentials")
            presented = value.strip()
        try:
            principal = repo.authenticate_api_key(presented or "")
        except Exception:
            raise HTTPException(status_code=503, detail="Authentication is unavailable") from None
        if principal is None:
            raise _unauthorized("Invalid credentials")
        return principal

    cookie = request.cookies.get(SESSION_COOKIE)
    if not cookie:
        raise _unauthorized()
    try:
        principal = repo.authenticate_session(cookie)
    except Exception:
        raise HTTPException(status_code=503, detail="Authentication is unavailable") from None
    if principal is None:
        raise _unauthorized("Session expired or invalid")
    if request.method not in SAFE_METHODS and not token_matches(
        request.headers.get(CSRF_HEADER), principal.csrf_hash
    ):
        raise HTTPException(status_code=403, detail="Missing or invalid CSRF token")
    return principal


def require_auth(request: Request, repo: AuthRepo = Depends(get_auth_repo)) -> None:
    """App-wide gate: authenticate every non-public route."""
    if is_public_path(request.url.path):
        return
    request.state.principal = authenticate(request, repo)


def get_principal(request: Request, repo: AuthRepo = Depends(get_auth_repo)) -> Principal:
    principal = getattr(request.state, "principal", None)
    if principal is None:
        principal = authenticate(request, repo)
        request.state.principal = principal
    return principal


def require(permission: str) -> Callable[..., Principal]:
    """Dependency factory: the principal, or 403 if it lacks ``permission``."""

    def dependency(principal: Principal = Depends(get_principal)) -> Principal:
        if not principal.can(permission):
            raise HTTPException(status_code=403, detail=f"Requires permission {permission}")
        return principal

    dependency.__name__ = f"require_{permission.replace(':', '_')}"
    return dependency
