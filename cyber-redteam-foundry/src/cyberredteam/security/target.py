"""Pure URL and address validation for server-side agent targets.

The checks here deliberately fail closed.  A URL is only a *candidate* target:
the networking layer must resolve its hostname without trusting environment
proxies, validate every returned address with :func:`validate_resolved_addresses`,
and disable redirects (or validate each redirect as a new target).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlsplit, urlunsplit


class TargetValidationError(ValueError):
    """Raised when a target is not safe to use for outbound verification."""


# Includes common metadata aliases in addition to the link-local IP addresses
# caught by address validation.  Hostname matching is exact/suffix based so a
# public hostname such as ``metadata.example.com`` remains valid.
_METADATA_HOSTS = frozenset(
    {
        "metadata",
        "metadata.google.internal",
        "metadata.google",
        "instance-data",
        "instance-data.ec2.internal",
    }
)
_LOCALHOST_SUFFIX = ".localhost"
_NUMERIC_LABEL = re.compile(r"^(?:0x[0-9a-f]+|[0-9]+)$", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class ValidatedTarget:
    """Canonical representation of a syntactically safe public target URL."""

    url: str
    origin: str
    scheme: str
    hostname: str
    port: int | None
    path: str
    query: str


def validate_target_url(value: str) -> ValidatedTarget:
    """Validate and normalize a candidate HTTP(S) target without network I/O.

    It rejects URL forms that can change authority interpretation (credentials,
    fragments, numeric host aliases) and literal addresses that are not globally
    routable.  DNS hostnames still require resolution-time validation.
    """

    if not isinstance(value, str) or not value.strip():
        raise TargetValidationError("target URL must be a non-empty string")
    if value != value.strip():
        raise TargetValidationError("target URL must not contain surrounding whitespace")

    try:
        parts = urlsplit(value)
    except ValueError as exc:
        raise TargetValidationError("target URL is malformed") from exc

    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        raise TargetValidationError("target URL scheme must be http or https")
    if not parts.netloc:
        raise TargetValidationError("target URL must include a hostname")
    if parts.username is not None or parts.password is not None:
        raise TargetValidationError("target URL must not include userinfo")
    if parts.fragment:
        raise TargetValidationError("target URL must not include a fragment")

    try:
        raw_hostname = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise TargetValidationError("target URL contains an invalid port") from exc
    if not raw_hostname:
        raise TargetValidationError("target URL must include a hostname")
    if "%" in raw_hostname:
        raise TargetValidationError("target URL must not include an IPv6 zone identifier")

    hostname = _normalize_hostname(raw_hostname)
    _validate_hostname(hostname)

    host_for_url = f"[{hostname}]" if _is_ip_literal(hostname, version=6) else hostname
    authority = host_for_url if port is None else f"{host_for_url}:{port}"
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    origin_authority = host_for_url if port is None or default_port else authority
    path = parts.path or "/"
    normalized = urlunsplit((scheme, authority, path, parts.query, ""))
    origin = f"{scheme}://{origin_authority}"
    return ValidatedTarget(
        url=normalized,
        origin=origin,
        scheme=scheme,
        hostname=hostname,
        port=port,
        path=path,
        query=parts.query,
    )


def validate_resolved_addresses(addresses: Iterable[str]) -> tuple[str, ...]:
    """Return canonical public addresses or raise if any address is unsafe.

    A hostname resolving to both a public and private address is rejected.  This
    prevents a caller from picking a convenient address and leaves no ambiguity
    for DNS-rebinding defenses.
    """

    normalized: list[str] = []
    for value in addresses:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise TargetValidationError("DNS returned an invalid IP address") from exc
        if address.version == 6 and address.ipv4_mapped is not None:
            raise TargetValidationError(f"IPv4-mapped IPv6 address is not allowed: {address}")
        if not _is_safe_public_address(address):
            raise TargetValidationError(f"target resolves to a non-public address: {address}")
        normalized.append(str(address))
    if not normalized:
        raise TargetValidationError("DNS returned no addresses")
    return tuple(normalized)


def _normalize_hostname(hostname: str) -> str:
    hostname = hostname.rstrip(".").lower()
    if not hostname:
        raise TargetValidationError("target URL must include a hostname")
    try:
        return hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise TargetValidationError("target hostname cannot be normalized") from exc


def _validate_hostname(hostname: str) -> None:
    if hostname == "localhost" or hostname.endswith(_LOCALHOST_SUFFIX):
        raise TargetValidationError("localhost targets are not allowed")
    if hostname in _METADATA_HOSTS:
        raise TargetValidationError("cloud metadata targets are not allowed")

    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        _reject_ambiguous_numeric_host(hostname)
        return
    if address.version == 6 and address.ipv4_mapped is not None:
        raise TargetValidationError("IPv4-mapped IPv6 target addresses are not allowed")
    if not _is_safe_public_address(address):
        raise TargetValidationError(f"target address is not public: {address}")


def _reject_ambiguous_numeric_host(hostname: str) -> None:
    """Reject forms some HTTP stacks reinterpret as loopback IP literals."""

    labels = hostname.split(".")
    if hostname.isdigit() or all(_NUMERIC_LABEL.fullmatch(label) for label in labels):
        raise TargetValidationError("numeric host aliases are not allowed")


def _is_ip_literal(hostname: str, *, version: int) -> bool:
    try:
        return ipaddress.ip_address(hostname).version == version
    except ValueError:
        return False


def _is_safe_public_address(address: ipaddress._BaseAddress) -> bool:
    """Reject every special-use range explicitly; ``is_global`` alone is not enough."""
    return bool(
        address.is_global
        and not address.is_private
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_multicast
        and not address.is_reserved
        and not address.is_unspecified
        and not (address.version == 6 and address.ipv4_mapped is not None)
    )
