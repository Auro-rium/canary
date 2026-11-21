"""Pluggable OIDC / OAuth2 login providers (WP8).

Flow: authorization code + PKCE (S256) + one-time ``state``. After the code
exchange the identity is read from the provider's userinfo endpoint over TLS
with the access token we just received directly from the token endpoint, so no
ID-token signature verification (and no JWT library) is needed.

Identity is ``(provider, subject)``; the subject is the provider's stable user
id (Google ``sub``, GitHub numeric ``id``), never the email.

Tests register :class:`FakeOIDCProvider`; real IdPs are never contacted in tests.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlencode

import httpx


@dataclass(frozen=True)
class OIDCIdentity:
    provider: str
    subject: str
    email: str | None
    email_verified: bool
    name: str = ""


class OIDCError(Exception):
    """Login failed at the identity provider. The message is a fixed string."""


class OIDCProvider(Protocol):
    name: str

    def authorization_url(self, *, state: str, code_challenge: str, redirect_uri: str) -> str: ...

    async def exchange(self, *, code: str, code_verifier: str, redirect_uri: str) -> OIDCIdentity: ...


def new_pkce() -> tuple[str, str]:
    """Return ``(code_verifier, S256 code_challenge)``."""
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=")
    return verifier, challenge.decode()


class _OAuthProvider:
    name = ""
    authorize_endpoint = ""
    token_endpoint = ""
    scope = ""

    def __init__(
        self, client_id: str, client_secret: str, *, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        self.client_id = client_id
        self._client_secret = client_secret
        self._transport = transport

    def authorization_url(self, *, state: str, code_challenge: str, redirect_uri: str) -> str:
        query = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "scope": self.scope,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        return f"{self.authorize_endpoint}?{urlencode(query)}"

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=10.0, follow_redirects=False, trust_env=False, transport=self._transport
        )

    async def _access_token(self, client: httpx.AsyncClient, code: str, verifier: str,
                            redirect_uri: str) -> str:
        resp = await client.post(
            self.token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": self.client_id,
                "client_secret": self._client_secret,
                "code_verifier": verifier,
            },
            headers={"Accept": "application/json"},
        )
        if resp.status_code != 200:
            raise OIDCError("token exchange failed")
        token = resp.json().get("access_token")
        if not isinstance(token, str) or not token:
            raise OIDCError("token exchange failed")
        return token


class GoogleProvider(_OAuthProvider):
    name = "google"
    authorize_endpoint = "https://accounts.google.com/o/oauth2/v2/auth"
    token_endpoint = "https://oauth2.googleapis.com/token"
    userinfo_endpoint = "https://openidconnect.googleapis.com/v1/userinfo"
    scope = "openid email profile"

    async def exchange(self, *, code: str, code_verifier: str, redirect_uri: str) -> OIDCIdentity:
        try:
            async with self._client() as client:
                token = await self._access_token(client, code, code_verifier, redirect_uri)
                resp = await client.get(
                    self.userinfo_endpoint, headers={"Authorization": f"Bearer {token}"}
                )
        except httpx.HTTPError:
            raise OIDCError("identity provider unreachable") from None
        if resp.status_code != 200:
            raise OIDCError("userinfo request failed")
        info = resp.json()
        sub = info.get("sub")
        if not isinstance(sub, str) or not sub:
            raise OIDCError("userinfo has no subject")
        return OIDCIdentity(
            provider=self.name, subject=sub, email=info.get("email"),
            email_verified=info.get("email_verified") is True, name=str(info.get("name") or ""),
        )


class GitHubProvider(_OAuthProvider):
    """GitHub OAuth app (GitHub is OAuth2, not OIDC; the stable subject is the numeric id)."""

    name = "github"
    authorize_endpoint = "https://github.com/login/oauth/authorize"
    token_endpoint = "https://github.com/login/oauth/access_token"
    scope = "read:user user:email"

    async def exchange(self, *, code: str, code_verifier: str, redirect_uri: str) -> OIDCIdentity:
        try:
            async with self._client() as client:
                token = await self._access_token(client, code, code_verifier, redirect_uri)
                headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
                user = await client.get("https://api.github.com/user", headers=headers)
                emails = await client.get("https://api.github.com/user/emails", headers=headers)
        except httpx.HTTPError:
            raise OIDCError("identity provider unreachable") from None
        if user.status_code != 200:
            raise OIDCError("userinfo request failed")
        info = user.json()
        uid = info.get("id")
        if not isinstance(uid, int):
            raise OIDCError("userinfo has no subject")
        email, verified = None, False
        if emails.status_code == 200 and isinstance(emails.json(), list):
            for item in emails.json():
                if isinstance(item, dict) and item.get("primary") and item.get("verified"):
                    email, verified = item.get("email"), True
        return OIDCIdentity(
            provider=self.name, subject=str(uid), email=email, email_verified=verified,
            name=str(info.get("name") or info.get("login") or ""),
        )


class FakeOIDCProvider:
    """In-process IdP for tests: ``issue(identity)`` returns a one-time code."""

    authorize_endpoint = "https://idp.invalid/authorize"

    def __init__(self, name: str = "fake") -> None:
        self.name = name
        self._codes: dict[str, tuple[OIDCIdentity, str]] = {}
        self.challenges: dict[str, str] = {}  # state -> code_challenge

    def authorization_url(self, *, state: str, code_challenge: str, redirect_uri: str) -> str:
        self.challenges[state] = code_challenge
        return f"{self.authorize_endpoint}?{urlencode({'state': state, 'redirect_uri': redirect_uri})}"

    def issue(self, identity: OIDCIdentity, state: str) -> str:
        code = secrets.token_urlsafe(16)
        self._codes[code] = (identity, self.challenges[state])
        return code

    async def exchange(self, *, code: str, code_verifier: str, redirect_uri: str) -> OIDCIdentity:
        entry = self._codes.pop(code, None)
        if entry is None:
            raise OIDCError("unknown code")
        identity, challenge = entry
        expected = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
        if expected.rstrip(b"=").decode() != challenge:
            raise OIDCError("PKCE verification failed")
        return identity


def configured_providers(settings) -> dict[str, OIDCProvider]:
    """Providers whose client id and secret are both configured."""
    out: dict[str, OIDCProvider] = {}
    gh_id, gh_secret = settings.oidc_github_client_id, settings.oidc_github_client_secret
    if gh_id and gh_secret:
        out["github"] = GitHubProvider(gh_id, gh_secret.get_secret_value())
    g_id, g_secret = settings.oidc_google_client_id, settings.oidc_google_client_secret
    if g_id and g_secret:
        out["google"] = GoogleProvider(g_id, g_secret.get_secret_value())
    return out
