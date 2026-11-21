"""Dev/test-only loopback allowance for the SSRF guard (Live test A harness).

Loopback is allowed only when CANARY_ENV is dev/test AND
CANARY_ALLOW_LOOPBACK_TARGETS=1. It never relaxes anything else.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from cyberredteam.jobs.runner_wiring import webhook_notifier
from cyberredteam.observability.wandb_metrics import _ssrf_guard
from cyberredteam.security import ownership
from cyberredteam.security.ownership import (
    TargetRefused,
    check_target_url,
    check_target_urls,
    loopback_targets_allowed,
    verify_ownership,
)
from cyberredteam.security.tokens import hash_verification_token

LOOPBACK_URLS = [
    "http://127.0.0.1:9000/chat",
    "http://localhost:9000/chat",
    "http://127.5.6.7/chat",
    "http://[::1]:9000/chat",
]
STILL_REFUSED = [
    "http://169.254.169.254/latest",
    "http://10.0.0.5/chat",
    "http://192.168.1.10/chat",
    "http://172.16.0.1/chat",
    "http://metadata.google.internal/x",
    "http://0.0.0.0/chat",
    "http://[::ffff:127.0.0.1]/chat",
    "http://127.1/chat",
    "http://2130706433/chat",
    "http://foo.localhost/chat",
]


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("CANARY_ALLOW_LOOPBACK_TARGETS", raising=False)
    monkeypatch.delenv("CANARY_ENV", raising=False)


def _enable(monkeypatch, env: str = "dev", flag: str = "1") -> None:
    monkeypatch.setenv("CANARY_ENV", env)
    monkeypatch.setenv("CANARY_ALLOW_LOOPBACK_TARGETS", flag)


@pytest.mark.parametrize("url", LOOPBACK_URLS)
def test_refused_by_default(url):
    with pytest.raises(TargetRefused):
        check_target_url(url)


@pytest.mark.parametrize("env", ["dev", "test", " DEV "])
@pytest.mark.parametrize("url", LOOPBACK_URLS)
def test_allowed_in_dev_and_test_with_flag(monkeypatch, env, url):
    _enable(monkeypatch, env)
    assert loopback_targets_allowed()
    check_target_url(url)


@pytest.mark.parametrize("env", ["production", "prod", "staging", "development", "local", ""])
def test_never_applies_outside_dev_and_test(monkeypatch, env):
    _enable(monkeypatch, env)
    assert not loopback_targets_allowed()
    for url in LOOPBACK_URLS:
        with pytest.raises(TargetRefused):
            check_target_url(url)


def test_unset_env_means_production(monkeypatch):
    monkeypatch.setenv("CANARY_ALLOW_LOOPBACK_TARGETS", "1")
    assert not loopback_targets_allowed()
    with pytest.raises(TargetRefused):
        check_target_url("http://127.0.0.1:9000/chat")


@pytest.mark.parametrize("flag", ["", "0", "true", "yes", "2"])
def test_dev_without_exact_flag_is_refused(monkeypatch, flag):
    _enable(monkeypatch, "dev", flag)
    assert not loopback_targets_allowed()
    with pytest.raises(TargetRefused):
        check_target_url("http://127.0.0.1:9000/chat")


@pytest.mark.parametrize("url", STILL_REFUSED)
def test_flag_does_not_open_anything_but_loopback(monkeypatch, url):
    _enable(monkeypatch)
    with pytest.raises(TargetRefused):
        check_target_url(url)


def test_settings_failure_fails_closed(monkeypatch):
    _enable(monkeypatch)

    def boom():
        raise RuntimeError("bad settings")

    monkeypatch.setattr("cyberredteam.settings.get_settings", boom)
    assert not loopback_targets_allowed()


# --- every call site goes through the same guard ---------------------------------


def test_registration_urls_guard(monkeypatch):
    url = "http://127.0.0.1:9000/chat"
    with pytest.raises(TargetRefused):
        check_target_urls(url, object())
    _enable(monkeypatch)
    check_target_urls(url, object())
    monkeypatch.setenv("CANARY_ENV", "production")
    with pytest.raises(TargetRefused):
        check_target_urls(url, object())


def test_verify_ownership_guard(monkeypatch):
    token = "tok-123"
    token_hash = hash_verification_token(token)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=token)

    transport = httpx.MockTransport(handler)
    url = "http://127.0.0.1:9000/chat"
    res = verify_ownership(url, token_hash, "http_wellknown", transport=transport)
    assert not res.verified and res.reason.startswith("refused")
    _enable(monkeypatch)
    assert verify_ownership(url, token_hash, "http_wellknown", transport=transport).verified
    monkeypatch.setenv("CANARY_ENV", "production")
    res = verify_ownership(url, token_hash, "http_wellknown", transport=transport)
    assert not res.verified and res.reason.startswith("refused")


def test_ops_webhook_guard(monkeypatch):
    url = "http://127.0.0.1:9100/hook"
    with pytest.raises(TargetRefused):
        _ssrf_guard(url)
    _enable(monkeypatch)
    _ssrf_guard(url)
    monkeypatch.setenv("CANARY_ENV", "production")
    with pytest.raises(TargetRefused):
        _ssrf_guard(url)


def test_oncall_webhook_guard(monkeypatch):
    url = "http://127.0.0.1:9100/hook"
    sent: list[str] = []

    class Tx:
        async def handle_async_request(self, request):
            sent.append(str(request.url))
            return httpx.Response(200, request=request)

        async def aclose(self):
            pass

    class Alert:
        def model_dump(self, mode="json"):
            return {"ok": True}

    notify = webhook_notifier(url, transport=Tx())
    with pytest.raises(TargetRefused):
        asyncio.run(notify(Alert()))
    assert sent == []
    _enable(monkeypatch)
    asyncio.run(notify(Alert()))
    assert sent == [url]
    monkeypatch.setenv("CANARY_ENV", "production")
    with pytest.raises(TargetRefused):
        asyncio.run(notify(Alert()))
    assert sent == [url]


def test_module_exposes_flag_name():
    assert ownership.LOOPBACK_FLAG_ENV == "CANARY_ALLOW_LOOPBACK_TARGETS"
