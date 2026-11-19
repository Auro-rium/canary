"""WP11 round-3 regressions."""

import logging
import os
import stat
import sys
import tempfile
import threading
import time
from types import SimpleNamespace

import pytest
from test_observability_metrics import FakeWandb

from cyberredteam.observability import redact
from cyberredteam.observability.setup import init_observability, reset_for_tests
from cyberredteam.observability.wandb_metrics import WandbCampaignMetrics, default_wandb_dir
from cyberredteam.storage.v2.redaction import redact as storage_redact


@pytest.fixture(autouse=True)
def _clean():
    redact.reset_state()
    yield
    redact.reset_state()


# ── 1. unterminated quotes redact to end of line ────────────────────────────

@pytest.mark.parametrize("text", [
    'Cookie: "session=SECRET1; k=v',
    "Cookie: 'session=SECRET1; k=v",
    'Set-Cookie: "session=SECRET1; Path=/',
    'curl https://x.test -u "admin:SECRET1 with space',
    "curl https://x.test -u 'admin:SECRET1 with space",
    'password="SECRET1 trailing',
    "api_key='SECRET1 trailing",
])
def test_unterminated_quotes_do_not_leak(text):
    assert "SECRET1" not in storage_redact(text).text
    assert "SECRET1" not in redact.redact_text(text)


def test_terminated_cookie_forms_still_work_and_following_lines_survive():
    out = storage_redact('Cookie: "a=SECRET1"\nnext line stays').text
    assert "SECRET1" not in out and "next line stays" in out
    out = storage_redact("Cookie: a=SECRET1; b=SECRET2\nkeep").text
    assert "SECRET" not in out and "keep" in out
    assert storage_redact('Cookie: "x\nsafe: 1').text.endswith("safe: 1")


def test_unterminated_cookie_straddling_the_4096_head():
    for pad in range(4040, 4100, 3):
        text = "w " * (pad // 2) + 'Cookie: "session=SECRETWORD; more=SECRETWORD'
        assert "SECRETWORD" not in redact.redact_text(text), pad


@pytest.mark.parametrize("offset", list(range(3700, 4500, 13)))
def test_long_unterminated_cookie_across_redact_long_boundary(offset):
    value = "session=SECRETWORD; " * 40  # > 512 chars, contains whitespace
    filler = "lorem ipsum dolor " * 500
    text = filler[:offset] + ' Cookie: "' + value + "\n" + filler
    out = redact.redact_long(text)
    assert "SECRETWORD" not in out
    assert out.rstrip().endswith("dolor")


def test_cookie_regex_is_linear():
    start = time.perf_counter()
    storage_redact('Cookie: "' * 11_000)
    storage_redact("Cookie: " + "a=b; " * 20_000)
    storage_redact('curl -u "' * 11_000)
    assert time.perf_counter() - start < 1.0


# ── 2. hex tokens after x / _ ───────────────────────────────────────────────

HEX64 = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"


@pytest.mark.parametrize("probe,needle", [
    ("0x" + HEX64, HEX64[:20]),
    ("id_" + HEX64[:32], HEX64[:20]),
    ("build_" + HEX64[:40], HEX64[:20]),
    ("key-" + HEX64[:32], HEX64[:20]),
    ("id_123456789012", "123456789012"),
])
def test_prefixed_hex_and_digit_tokens_are_masked(probe, needle):
    assert needle not in redact.preview(probe)
    assert needle not in repr(redact.sanitize({"v": f"see {probe} ok"}))


# ── hardening ───────────────────────────────────────────────────────────────

def test_run_finished_immediately_if_it_lands_after_close_finalized():
    gate = threading.Event()

    class Slow(FakeWandb):
        def init(self, **kw):
            gate.wait(5)
            return super().init(**kw)

    sdk = Slow()
    m = WandbCampaignMetrics(wandb_module=sdk)
    m.campaign_started("a", {})
    time.sleep(0.1)  # worker is inside init
    m.close(timeout=0.2)
    gate.set()
    time.sleep(0.3)
    assert sdk.run.finished and "a" not in m._runs


def test_default_wandb_dir_is_per_user_and_private():
    path = default_wandb_dir()
    assert path and path.startswith(tempfile.gettempdir())
    if hasattr(os, "getuid"):
        assert str(os.getuid()) in os.path.basename(path)
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o700


def test_foreign_owned_wandb_dir_fails_closed(monkeypatch):
    if not hasattr(os, "getuid"):
        pytest.skip("posix only")
    real = os.lstat

    def fake(path, *a, **k):
        st = real(path, *a, **k)
        if "canary-wandb" in str(path):
            return SimpleNamespace(st_uid=os.getuid() + 1, st_mode=st.st_mode)
        return st

    monkeypatch.setattr(os, "lstat", fake)
    assert default_wandb_dir() is None
    sdk = FakeWandb()
    m = WandbCampaignMetrics(wandb_module=sdk)
    m.campaign_started("c", {})
    assert m.flush(5)
    assert sdk.kw == {}  # W&B skipped entirely


def test_local_logs_carry_exception_type_only(caplog):
    class Down:
        class Settings:
            def __init__(self, **kw):
                pass

        def init(self, **kw):
            raise ConnectionError("LEAKY-MESSAGE-SECRET")

    with caplog.at_level(logging.DEBUG):
        m = WandbCampaignMetrics(wandb_module=Down())
        m.campaign_started("c", {})
        assert m.flush(5)
    assert "LEAKY-MESSAGE-SECRET" not in caplog.text
    assert "ConnectionError" in caplog.text


def test_reset_for_tests_resets_hash_key_secrets_and_raw_flag():
    redact.configure_hash_key("k")
    redact.register_secret("some-registered-secret")
    redact.configure_raw_export(True)
    reset_for_tests()
    assert redact.hash_marker("x").startswith("[REDACTED:text")
    assert "some-registered-secret" not in redact._known_secrets
    assert redact._flag_raw is False


def test_init_observability_installs_the_hash_key():
    class S:
        wandb_api_key = None
        wandb_mode = "disabled"
        wandb_entity = None
        wandb_project = "canary"
        wandb_export_raw_evidence = False
        canary_encryption_key = "deployment-encryption-key"

    reset_for_tests()
    try:
        init_observability(S())
        assert redact.hash_marker("123-45-6789").startswith("[hmac:")
    finally:
        reset_for_tests()


def test_dict_keys_and_alert_text_fail_closed_without_redactor(monkeypatch):
    monkeypatch.setitem(sys.modules, "cyberredteam.storage.v2.redaction", None)
    out = redact.sanitize({"free text key 123": 1})
    assert list(out) == ["[REDACTED:text len=17]"]
    from cyberredteam.observability.wandb_metrics import sanitize_alert

    assert sanitize_alert("secret detail here") == "[REDACTED:text len=18]"
