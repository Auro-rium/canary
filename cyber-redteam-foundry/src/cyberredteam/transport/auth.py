"""Auth strategies for the session adapter.

Secrets are read with ``.get_secret_value()`` only at request time, are never
logged and never put into exception messages.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import httpx

from cyberredteam.contracts import (
    BearerAuth,
    CookieLoginAuth,
    HeaderAuth,
    OAuthClientCredentialsAuth,
    TargetAuth,
)

REFRESH_SKEW_S = 30.0
DEFAULT_TOKEN_TTL_S = 3600.0


class AuthFailure(Exception):
    """Login or token fetch failed. ``kind`` is a TargetErrorKind value; the
    message never includes credentials or response bodies."""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind


class AuthStrategy:
    """Base strategy: no auth."""

    async def headers(self, client: httpx.AsyncClient) -> dict[str, str]:
        return {}

    async def refresh_after_401(self, client: httpx.AsyncClient) -> bool:
        """Re-authenticate after a 401. Return True if the request may be retried."""
        return False


class _Bearer(AuthStrategy):
    def __init__(self, auth: BearerAuth) -> None:
        self._auth = auth

    async def headers(self, client: httpx.AsyncClient) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._auth.token.get_secret_value()}"}


class _Header(AuthStrategy):
    def __init__(self, auth: HeaderAuth) -> None:
        self._auth = auth

    async def headers(self, client: httpx.AsyncClient) -> dict[str, str]:
        return {self._auth.header_name: self._auth.value.get_secret_value()}


def _failure_from_status(status: int, what: str) -> AuthFailure:
    kind = "http_5xx" if status >= 500 else "http_4xx"
    return AuthFailure(kind, f"{what} returned HTTP {status}")


def _failure_from_exception(exc: Exception, what: str) -> AuthFailure:
    if isinstance(exc, httpx.TimeoutException):
        return AuthFailure("timeout", f"{what} timed out")
    return AuthFailure("unreachable", f"{what} failed ({type(exc).__name__})")


class _OAuth(AuthStrategy):
    def __init__(self, auth: OAuthClientCredentialsAuth, clock: Callable[[], float]) -> None:
        self._auth = auth
        self._clock = clock
        self._token: str | None = None
        self._expires_at = 0.0

    def _valid(self) -> bool:
        return self._token is not None and self._clock() < self._expires_at - REFRESH_SKEW_S

    async def _fetch(self, client: httpx.AsyncClient) -> None:
        form: dict[str, str] = {
            "grant_type": "client_credentials",
            "client_id": self._auth.client_id,
            "client_secret": self._auth.client_secret.get_secret_value(),
        }
        if self._auth.scope:
            form["scope"] = self._auth.scope
        if self._auth.audience:
            form["audience"] = self._auth.audience
        try:
            resp = await client.post(str(self._auth.token_url), data=form)
        except httpx.HTTPError as exc:
            raise _failure_from_exception(exc, "token request") from None
        if resp.status_code >= 400:
            raise _failure_from_status(resp.status_code, "token request")
        try:
            data: Any = resp.json()
            token = data["access_token"]
            ttl = float(data.get("expires_in", DEFAULT_TOKEN_TTL_S))
        except (ValueError, KeyError, TypeError, AttributeError):
            raise AuthFailure("bad_json", "token response had no usable access_token") from None
        if not isinstance(token, str) or not token:
            raise AuthFailure("bad_json", "token response had no usable access_token")
        self._token = token
        self._expires_at = self._clock() + ttl

    async def headers(self, client: httpx.AsyncClient) -> dict[str, str]:
        if not self._valid():
            await self._fetch(client)
        return {"Authorization": f"Bearer {self._token}"}

    async def refresh_after_401(self, client: httpx.AsyncClient) -> bool:
        self._token = None
        await self._fetch(client)
        return True


class _CookieLogin(AuthStrategy):
    """Logs in once; the session cookie then lives in the client's cookie jar."""

    def __init__(self, auth: CookieLoginAuth) -> None:
        self._auth = auth
        self._logged_in = False

    async def _login(self, client: httpx.AsyncClient) -> None:
        body = {
            self._auth.username_field: self._auth.username,
            self._auth.password_field: self._auth.password.get_secret_value(),
        }
        try:
            resp = await client.post(str(self._auth.login_url), json=body)
        except httpx.HTTPError as exc:
            raise _failure_from_exception(exc, "login request") from None
        if resp.status_code >= 400:
            raise _failure_from_status(resp.status_code, "login request")
        self._logged_in = True

    async def headers(self, client: httpx.AsyncClient) -> dict[str, str]:
        if not self._logged_in:
            await self._login(client)
        return {}

    async def refresh_after_401(self, client: httpx.AsyncClient) -> bool:
        self._logged_in = False
        await self._login(client)
        return True


def build_auth(auth: TargetAuth, clock: Callable[[], float] = time.monotonic) -> AuthStrategy:
    if isinstance(auth, BearerAuth):
        return _Bearer(auth)
    if isinstance(auth, HeaderAuth):
        return _Header(auth)
    if isinstance(auth, OAuthClientCredentialsAuth):
        return _OAuth(auth, clock)
    if isinstance(auth, CookieLoginAuth):
        return _CookieLogin(auth)
    return AuthStrategy()
