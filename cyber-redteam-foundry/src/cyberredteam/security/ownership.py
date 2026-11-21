"""Target ownership verification.

An operator proves they control a target by publishing the per-target token
(issued once at registration, see :mod:`cyberredteam.security.tokens`) in one
of three places:

``http_wellknown``
    ``GET {origin}/.well-known/canary-verify.txt`` returns the token (one line).
``dns_txt``
    A TXT record ``_canary-verify.<host>`` whose value is the token.
``response_header``
    The target's endpoint returns ``X-Canary-Verify: <token>`` on a benign
    request (``GET``, then an empty-JSON ``POST`` if the header is absent).

Only the token's digest is stored, so every candidate value fetched from the
target is hashed and compared in constant time.

Network safety (fail closed):

* The URL must be ``http``/``https`` with no userinfo or fragment.
* Unless ``allow_private_targets=True`` is passed explicitly, ``localhost``
  names, cloud-metadata names, numeric host aliases, and any host that is or
  resolves to a private, loopback, link-local, multicast, reserved or
  unspecified address are refused. A host resolving to a mix of public and
  private addresses is refused.
* Dev/test only: loopback (``localhost``, 127.0.0.0/8, ``::1``) is allowed when
  ``CANARY_ENV`` is ``dev`` or ``test`` AND ``CANARY_ALLOW_LOOPBACK_TARGETS=1``.
  Nothing else is relaxed (private ranges, link-local, metadata names stay
  refused), and it never applies in production. See :func:`loopback_targets_allowed`.
* Redirects are never followed automatically. A redirect to the same host is
  followed (at most ``MAX_REDIRECTS``, no https->http downgrade, re-checked);
  a redirect to any other host is refused.
* Short timeouts; environment proxies are ignored; response bodies are capped.

Known limit: the address check runs at verify time, before httpx resolves the
name again, so a DNS-rebinding host could still swap addresses in between. The
WP2 ``SessionAdapter`` must re-apply :func:`check_target_url` at send time.

Ported in part from ``security/target.py`` on
``feature/cutc-2026-differential-gate``.
"""

from __future__ import annotations

import ipaddress
import os
import re
import socket
from dataclasses import dataclass
from typing import Callable, Iterable
from urllib.parse import urljoin, urlsplit

import httpx

from cyberredteam.security.tokens import verify_verification_token

WELL_KNOWN_PATH = "/.well-known/canary-verify.txt"
DNS_TXT_PREFIX = "_canary-verify."
VERIFY_HEADER = "X-Canary-Verify"

HTTP_WELLKNOWN = "http_wellknown"
DNS_TXT = "dns_txt"
RESPONSE_HEADER = "response_header"
METHODS = (HTTP_WELLKNOWN, DNS_TXT, RESPONSE_HEADER)

DEFAULT_TIMEOUT_S = 5.0
MAX_REDIRECTS = 3
MAX_BODY_BYTES = 4096
MAX_CANDIDATES = 20
USER_AGENT = "canary-ownership-check/1"

HostResolver = Callable[[str], Iterable[str]]
TxtResolver = Callable[[str, float], Iterable[str]]


class TargetRefused(ValueError):
    """The target URL (or a redirect) is not safe to contact."""


@dataclass(frozen=True)
class VerificationResult:
    verified: bool
    method: str
    reason: str


# ── URL / address guard ──────────────────────────────────────────────────────

_METADATA_HOSTS = frozenset(
    {
        "metadata",
        "metadata.google.internal",
        "metadata.google",
        "instance-data",
        "instance-data.ec2.internal",
    }
)
_NUMERIC_LABEL = re.compile(r"^(?:0x[0-9a-f]+|[0-9]+)$", re.IGNORECASE)


def _is_public(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    # ``is_global`` alone is not enough; reject every special-use range.
    if address.version == 6 and address.ipv4_mapped is not None:
        return False
    return bool(
        address.is_global
        and not address.is_private
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_multicast
        and not address.is_reserved
        and not address.is_unspecified
    )


LOOPBACK_FLAG_ENV = "CANARY_ALLOW_LOOPBACK_TARGETS"


def loopback_targets_allowed() -> bool:
    """True only for CANARY_ENV in {dev, test} with CANARY_ALLOW_LOOPBACK_TARGETS=1.

    Fails closed: any error reading the settings, or any other environment name
    (including ``production`` and an unset value), returns False.
    """
    if os.environ.get(LOOPBACK_FLAG_ENV, "").strip() != "1":
        return False
    try:
        from cyberredteam.settings import get_settings

        env = get_settings().canary_env.strip().lower()
    except Exception:  # noqa: BLE001 - fail closed
        return False
    return env in {"dev", "test"}


def _is_loopback_host(hostname: str) -> bool:
    if hostname == "localhost":
        return True
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        return False
    if literal.version == 6 and literal.ipv4_mapped is not None:
        return False
    return literal.is_loopback


def default_resolve_host(hostname: str) -> list[str]:
    """Resolve A/AAAA records with the system resolver."""
    infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    return sorted({info[4][0] for info in infos})


def check_target_url(
    url: str,
    *,
    allow_private_targets: bool = False,
    resolve_host: HostResolver | None = None,
) -> tuple[str, str]:
    """Validate ``url``; return ``(scheme, hostname)`` or raise :class:`TargetRefused`."""
    try:
        parts = urlsplit(url)
        hostname = parts.hostname
        _ = parts.port  # raises ValueError on an invalid port
    except ValueError as exc:
        raise TargetRefused("target URL is malformed") from exc
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        raise TargetRefused("target URL scheme must be http or https")
    if parts.username is not None or parts.password is not None:
        raise TargetRefused("target URL must not include userinfo")
    if parts.fragment:
        raise TargetRefused("target URL must not include a fragment")
    if not hostname:
        raise TargetRefused("target URL must include a hostname")
    hostname = hostname.rstrip(".").lower()
    if not hostname or "%" in hostname:
        raise TargetRefused("target hostname is not allowed")

    if allow_private_targets:
        return scheme, hostname

    if _is_loopback_host(hostname) and loopback_targets_allowed():
        return scheme, hostname
    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise TargetRefused("localhost targets are not allowed")
    if hostname in _METADATA_HOSTS:
        raise TargetRefused("cloud metadata targets are not allowed")
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        literal = None
    if literal is not None:
        if not _is_public(literal):
            raise TargetRefused(f"target address is not public: {literal}")
        return scheme, hostname
    labels = hostname.split(".")
    if all(_NUMERIC_LABEL.fullmatch(label) for label in labels):
        raise TargetRefused("numeric host aliases are not allowed")

    resolver = resolve_host or default_resolve_host
    try:
        addresses = list(resolver(hostname))
    except Exception as exc:  # noqa: BLE001 - any resolver failure fails closed
        raise TargetRefused(f"could not resolve target host ({type(exc).__name__})") from None
    if not addresses:
        raise TargetRefused("target host did not resolve")
    for raw in addresses:
        try:
            address = ipaddress.ip_address(raw)
        except ValueError:
            raise TargetRefused("target host resolved to an invalid address") from None
        if not _is_public(address):
            raise TargetRefused(f"target resolves to a non-public address: {address}")
    return scheme, hostname


# ── Auth URL host binding ────────────────────────────────────────────────────

def _auth_urls(auth: object) -> list[tuple[str, str]]:
    """``(field, url)`` pairs of an auth config that receive credentials."""
    pairs = []
    for name in ("token_url", "login_url"):
        value = getattr(auth, name, None)
        if value is not None:
            pairs.append((name, str(value)))
    return pairs


def check_target_urls(
    endpoint: str,
    auth: object,
    allowed_auth_hosts: Iterable[str] = (),
    *,
    allow_private_targets: bool = False,
    resolve_host: HostResolver | None = None,
) -> None:
    """Guard every URL of a target that Canary will send traffic or credentials to.

    The endpoint and any ``token_url`` / ``login_url`` must pass
    :func:`check_target_url`. Each auth URL's host must also **equal** the
    endpoint's host or be listed exactly in ``allowed_auth_hosts``, so
    credentials cannot be sent to a third-party host. Same-"registrable domain"
    is deliberately not used: without the Public Suffix List it fails open on
    shared hosting (``victim.herokuapp.com`` vs ``attacker.herokuapp.com``).
    Raises :class:`TargetRefused`.
    """
    _, endpoint_host = check_target_url(
        endpoint, allow_private_targets=allow_private_targets, resolve_host=resolve_host
    )
    allowed = {h.strip().rstrip(".").lower() for h in allowed_auth_hosts if h and h.strip()}
    for name, url in _auth_urls(auth):
        try:
            _, host = check_target_url(
                url, allow_private_targets=allow_private_targets, resolve_host=resolve_host
            )
        except TargetRefused as exc:
            raise TargetRefused(f"{name}: {exc}") from None
        if host != endpoint_host and host not in allowed:
            raise TargetRefused(
                f"{name} host {host!r} is not the endpoint's host; "
                "list it in allowed_auth_hosts to permit it"
            )


# ── HTTP helpers ─────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class _Fetched:
    status: int
    headers: httpx.Headers
    body: bytes


def _effective_port(url: str) -> int | None:
    parts = urlsplit(url)
    return parts.port or {"http": 80, "https": 443}.get(parts.scheme.lower())


def _fetch(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    json_body: object | None,
    allow_private_targets: bool,
    resolve_host: HostResolver | None,
) -> _Fetched:
    scheme, host = check_target_url(
        url, allow_private_targets=allow_private_targets, resolve_host=resolve_host
    )
    for _ in range(MAX_REDIRECTS + 1):
        kwargs = {"json": json_body} if (method == "POST" and json_body is not None) else {}
        request = client.build_request(method, url, **kwargs)
        response = client.send(request, stream=True, follow_redirects=False)
        try:
            body = b""
            if not response.is_redirect:
                for chunk in response.iter_bytes():
                    body += chunk
                    if len(body) >= MAX_BODY_BYTES:
                        body = body[:MAX_BODY_BYTES]
                        break
            fetched = _Fetched(response.status_code, response.headers, body)
            location = response.headers.get("location") if response.is_redirect else None
        finally:
            response.close()
        if location is None:
            return fetched

        next_url = urljoin(url, location)
        next_scheme, next_host = check_target_url(
            next_url, allow_private_targets=allow_private_targets, resolve_host=resolve_host
        )
        if next_host != host:
            raise TargetRefused("redirect to another host refused")
        if scheme == "https" and next_scheme != "https":
            raise TargetRefused("redirect from https to http refused")
        if _effective_port(next_url) != _effective_port(url):
            raise TargetRefused("redirect to another port refused")
        if fetched.status not in (307, 308):
            method, json_body = "GET", None
        url, scheme = next_url, next_scheme
    raise TargetRefused(f"too many redirects (max {MAX_REDIRECTS})")


def _matches(candidates: Iterable[str], token_hash: str) -> bool:
    found = False
    for i, candidate in enumerate(candidates):
        if i >= MAX_CANDIDATES:
            break
        # Evaluate every candidate (no early exit) to keep timing uniform.
        if verify_verification_token(candidate.strip(), token_hash):
            found = True
    return found


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


# ── DNS helper ───────────────────────────────────────────────────────────────


def default_txt_resolver(name: str, timeout_s: float) -> list[str]:
    """Return the TXT values for ``name``; raise ``TimeoutError`` on timeout."""
    import dns.exception
    import dns.resolver

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout_s
    resolver.lifetime = timeout_s
    try:
        answer = resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.Timeout:
        raise TimeoutError("DNS lookup timed out") from None
    return [b"".join(rdata.strings).decode("utf-8", "replace") for rdata in answer]


# ── Public entry point ───────────────────────────────────────────────────────


def verify_ownership(
    endpoint: str,
    token_hash: str,
    method: str,
    *,
    allow_private_targets: bool = False,
    transport: httpx.BaseTransport | None = None,
    resolve_host: HostResolver | None = None,
    txt_resolver: TxtResolver | None = None,
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> VerificationResult:
    """Check that the target at ``endpoint`` publishes the token for ``token_hash``.

    Never raises for network or policy failures: the outcome and a short reason
    (which never contains fetched content or the token) are returned.
    """
    if method not in METHODS:
        raise ValueError(f"unknown verification method {method!r}; expected one of {METHODS}")
    if not token_hash:
        return VerificationResult(False, method, "no verification token issued for this target")

    def fail(reason: str) -> VerificationResult:
        return VerificationResult(False, method, reason)

    try:
        _, hostname = check_target_url(
            endpoint, allow_private_targets=allow_private_targets, resolve_host=resolve_host
        )
        if method == DNS_TXT:
            try:
                ipaddress.ip_address(hostname)
                return fail("DNS TXT verification needs a hostname, not an IP address")
            except ValueError:
                pass
            resolver = txt_resolver or default_txt_resolver
            try:
                values = list(resolver(DNS_TXT_PREFIX + hostname, timeout_s))
            except TimeoutError:
                return fail("timeout")
            except Exception as exc:  # noqa: BLE001 - resolver failures fail closed
                return fail(f"DNS lookup failed ({type(exc).__name__})")
            if _matches(values, token_hash):
                return VerificationResult(True, method, "token found in DNS TXT record")
            return fail(f"no matching TXT record at {DNS_TXT_PREFIX}{hostname}")

        with httpx.Client(
            transport=transport,
            timeout=httpx.Timeout(timeout_s),
            follow_redirects=False,
            trust_env=False,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            common = {
                "allow_private_targets": allow_private_targets,
                "resolve_host": resolve_host,
            }
            if method == HTTP_WELLKNOWN:
                fetched = _fetch(
                    client, "GET", _origin(endpoint) + WELL_KNOWN_PATH, json_body=None, **common
                )
                if fetched.status != 200:
                    return fail("well-known file not available")
                lines = fetched.body.decode("utf-8", "replace").splitlines()
                if _matches(lines, token_hash):
                    return VerificationResult(True, method, "token found in well-known file")
                return fail("well-known file does not contain the token")

            # RESPONSE_HEADER
            fetched = _fetch(client, "GET", endpoint, json_body=None, **common)
            values = fetched.headers.get_list(VERIFY_HEADER)
            if not values:
                fetched = _fetch(client, "POST", endpoint, json_body={}, **common)
                values = fetched.headers.get_list(VERIFY_HEADER)
            if not values:
                return fail(f"endpoint did not return a {VERIFY_HEADER} header")
            if _matches(values, token_hash):
                return VerificationResult(True, method, f"token found in {VERIFY_HEADER} header")
            return fail(f"{VERIFY_HEADER} header does not match the token")
    except TargetRefused as exc:
        return fail(f"refused: {exc}")
    except httpx.TimeoutException:
        return fail("timeout")
    except (httpx.HTTPError, httpx.InvalidURL) as exc:
        return fail(f"request failed ({type(exc).__name__})")
    except Exception:  # noqa: BLE001 - verification must fail closed, never 500
        return fail("request failed")
