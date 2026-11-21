"""WP8: the target's on-call webhook (stored encrypted) is the worker's
``EngineDeps.on_call`` hook. Alerts carry ids and hit names only; the URL is
SSRF-checked before every send, redirects are not followed, and it is never logged."""

from __future__ import annotations

import asyncio
import json
import logging
from types import SimpleNamespace

import httpx
import pytest
from storage_v2_support import make_target

from cyberredteam.engine.types import OnCallAlert
from cyberredteam.jobs.runner_wiring import _target_webhook_notifier, webhook_notifier
from cyberredteam.security.ownership import TargetRefused
from cyberredteam.storage.v2.repositories import SqlTargetStore

URL = "https://hooks.example.com/services/T0/B0/HOOK-SECRET-abc"


def _alert():
    return OnCallAlert(campaign_id="c1", conversation_id="conv1", target_id="t1",
                       environment="production", turn_index=2, hits=["pii_email"])


def test_posts_the_alert_once_without_following_redirects(caplog):
    sent, checked = [], []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(302, headers={"location": "http://169.254.169.254/"})

    notify = webhook_notifier(URL, url_check=checked.append, transport=httpx.MockTransport(handler))
    with caplog.at_level(logging.DEBUG):
        asyncio.run(notify(_alert()))
    assert checked == [URL] and len(sent) == 1
    body = json.loads(sent[0].content)
    assert body == _alert().model_dump(mode="json")
    assert "HOOK-SECRET" not in caplog.text


def test_error_status_raises_without_the_url():
    notify = webhook_notifier(URL, url_check=lambda u: None,
                              transport=httpx.MockTransport(lambda r: httpx.Response(500)))
    with pytest.raises(RuntimeError) as exc:
        asyncio.run(notify(_alert()))
    assert "HOOK-SECRET" not in str(exc.value)


def test_private_webhook_refused_before_any_request():
    sent = []
    notify = webhook_notifier("http://127.0.0.1:9/hook",
                              transport=httpx.MockTransport(lambda r: sent.append(r) or httpx.Response(200)))
    with pytest.raises(TargetRefused):
        asyncio.run(notify(_alert()))
    assert sent == []


def test_runner_uses_the_stored_webhook(db_factory):
    store = SqlTargetStore(db_factory)
    with_hook = make_target()
    store.create(with_hook, oncall_webhook=URL)
    without = make_target()
    store.create(without)
    runtime = SimpleNamespace(targets=store)
    assert callable(_target_webhook_notifier(runtime, with_hook.target_id))
    assert _target_webhook_notifier(runtime, without.target_id) is None
    assert _target_webhook_notifier(SimpleNamespace(), with_hook.target_id) is None
