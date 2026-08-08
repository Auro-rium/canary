from __future__ import annotations

import pytest

from cyberredteam.security.target import (
    TargetValidationError,
    validate_resolved_addresses,
    validate_target_url,
)


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com",
        "file:///etc/passwd",
        "https://user:password@example.com",
        "https://localhost/agent",
        "https://api.localhost/agent",
        "http://127.0.0.1/agent",
        "http://10.1.2.3/agent",
        "http://172.16.0.1/agent",
        "http://192.168.0.1/agent",
        "http://169.254.169.254/latest/meta-data",
        "http://metadata.google.internal/computeMetadata/v1",
        "http://[::1]/agent",
        "http://[fe80::1]/agent",
        "http://[ff00::1]/agent",
        "http://0.0.0.0/agent",
        "http://224.0.0.1/agent",
        "http://2130706433/agent",
        "http://0177.0.0.1/agent",
        "https://example.com/#fragment",
    ],
)
def test_rejects_unsafe_or_unsupported_urls(url: str) -> None:
    with pytest.raises(TargetValidationError):
        validate_target_url(url)


def test_normalizes_origin_and_default_port() -> None:
    target = validate_target_url("HTTPS://Example.COM:443/v1/chat?debug=0")

    assert target.origin == "https://example.com"
    assert target.url == "https://example.com:443/v1/chat?debug=0"
    assert target.hostname == "example.com"
    assert target.port == 443


def test_keeps_non_default_port_in_origin() -> None:
    target = validate_target_url("https://example.com:8443/agent")

    assert target.origin == "https://example.com:8443"


def test_public_ip_literal_is_allowed() -> None:
    target = validate_target_url("https://8.8.8.8/agent")

    assert target.hostname == "8.8.8.8"


def test_resolution_rejects_mixed_private_and_public_answers() -> None:
    with pytest.raises(TargetValidationError):
        validate_resolved_addresses(["8.8.8.8", "127.0.0.1"])


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.1", "169.254.169.254", "0.0.0.0", "ff00::1"])
def test_resolution_rejects_non_public_addresses(address: str) -> None:
    with pytest.raises(TargetValidationError):
        validate_resolved_addresses([address])


def test_resolution_normalizes_public_addresses() -> None:
    assert validate_resolved_addresses(["8.8.8.8", "2001:4860:4860::8888"]) == (
        "8.8.8.8",
        "2001:4860:4860::8888",
    )
