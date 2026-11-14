"""WP11 re-review regressions."""

import os
import tempfile
import threading
import time

import pytest
from test_observability_metrics import FakeWandb  # noqa: I001

from cyberredteam.observability import redact
from cyberredteam.observability.wandb_metrics import WandbCampaignMetrics


@pytest.fixture(autouse=True)
def _clean():
    redact.configure_hash_key("test-deployment-key")
    redact.configure_raw_export(False)
    redact._known_secrets.clear()
    yield
    redact.configure_hash_key(None)
    redact.configure_raw_export(False)
    redact._known_secrets.clear()


# ── 1. preview must not pass sensitive-looking ids through ──────────────────

@pytest.mark.parametrize("probe", [
    "4111111111111111",            # card number
    "123456789",                   # SSN without dashes
    "5551234567",                  # phone number
    "d41d8cd98f00b204e9800998ecf8427e",            # 32-hex key
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",    # 40-hex key
    "0b1c2d3e-4f50-6789-abcd-ef0123456789",        # uuid-shaped key
])
def test_preview_does_not_pass_ids_and_digits_raw(probe):
    assert probe not in redact.preview(probe)
    assert probe not in redact.preview(probe, hashes=False)
    assert probe not in repr(redact.sanitize({"v": probe}))


def test_registered_hex_secret_is_masked_first():
    secret = "feedfacecafebeef0123456789abcdef"
    redact.register_secret(secret)
    assert secret not in redact.preview(secret)
    assert secret not in repr(redact.sanitize([secret, {"k": secret}]))


def test_own_hash_marker_still_passes_through():
    marker = redact.hash_marker("something")
    assert redact.preview(marker) == marker


# ── 6. exceptions: class name + hash unless raw export is allowed ───────────

def test_exception_message_hash_only_by_default_preview_only_when_raw():
    exc = ValueError("free text evidence patient Zed Q. Public lives on Elm St")
    msg = redact.safe_exception_message(exc)
    assert msg.startswith("ValueError [hmac:") and "Elm St" not in msg
    redact.configure_raw_export(True)
    token = redact.set_environment("staging")
    try:
        assert "Elm St" in redact.safe_exception_message(exc)
    finally:
        redact.reset_environment(token)


# ── 8. long reports are redacted in full, in overlapping chunks ─────────────

SECRET_LINE = 'api_key = "SUPERSECRETKEY1234567890abcdef"'


@pytest.mark.parametrize("offset", list(range(3900, 4300, 7)))
def test_redact_long_masks_secrets_straddling_chunk_boundaries(offset):
    filler = "lorem ipsum dolor sit amet " * 400
    text = filler[:offset] + " " + SECRET_LINE + " " + filler + "TAIL-MARKER-END"
    out = redact.redact_long(text)
    assert "SUPERSECRETKEY" not in out
    assert out.endswith("TAIL-MARKER-END")  # the whole report is kept
    assert len(out) > 0.8 * len(filler)


def test_redact_long_masks_private_key_spanning_chunks():
    pem = "-----BEGIN RSA PRIVATE KEY-----\n" + "MIIEowIBAAKCAQEA" * 250 + "\n-----END RSA PRIVATE KEY-----"
    text = "word " * 780 + pem + " tail-ok " + "word " * 3000
    out = redact.redact_long(text)
    assert "MIIEowIBAAKCAQEA" not in out and "tail-ok" in out


def test_report_artifact_keeps_full_report_and_masks_every_chunk():
    sdk = FakeWandb()
    m = WandbCampaignMetrics(wandb_module=sdk)
    body = ("section text " * 700 + SECRET_LINE + "\n") * 3 + "THE-END"
    m.campaign_started("c", {"environment": "production"})
    m.campaign_finished("c", {"report_markdown": body})
    assert m.flush(10)
    out = sdk.run.artifacts[0].files["report.md"]
    assert "SUPERSECRETKEY" not in out and out.endswith("THE-END")


# ── 4. Settings failure skips W&B (no fail-open) ────────────────────────────

def test_settings_failure_skips_wandb_and_trips_breaker():
    class Bad(FakeWandb):
        class Settings:
            def __init__(self, **kw):
                raise ValueError("bad settings")

    sdk = Bad()
    m = WandbCampaignMetrics(wandb_module=sdk)
    m.campaign_started("c", {})
    m.service_started("api")
    assert m.flush(5)
    assert sdk.kw == {}  # wandb.init was never called with default settings
    assert not m.breaker.allow()


# ── 5. shutdown ─────────────────────────────────────────────────────────────

def test_close_delivers_queued_campaign_finished_and_then_accepts_nothing():
    sdk = FakeWandb()
    m = WandbCampaignMetrics(wandb_module=sdk)
    m.campaign_started("c", {"environment": "production"})
    m.log("c", {"x": 1.0}, step=1)
    m.campaign_finished("c", {"headline": {"asr": 0.5}, "report_markdown": "# r"})
    m.close()  # no flush: close itself must drain
    assert sdk.run.summary.get("asr") == 0.5 and sdk.run.artifacts and sdk.run.finished
    sdk.run.logged.clear()
    m.campaign_started("late", {})
    m.log("late", {"x": 1.0})
    time.sleep(0.05)
    assert "late" not in m._runs and sdk.run.logged == []


def test_worker_outliving_close_creates_no_runs():
    gate = threading.Event()

    class Slow(FakeWandb):
        def init(self, **kw):
            gate.wait(5)
            return super().init(**kw)

    sdk = Slow()
    m = WandbCampaignMetrics(wandb_module=sdk)
    m.campaign_started("a", {})
    m.campaign_started("b", {})
    m.close(timeout=0.2)  # worker is still stuck in the first init
    gate.set()
    time.sleep(0.3)
    assert "b" not in m._runs  # second queued init refused after close() gave up


def test_api_registers_shutdown_hook_that_closes_metrics(monkeypatch):
    from cyberredteam import api
    from cyberredteam.observability import setup

    assert any(h.__name__ == "stop_observability" for h in api.app.router.on_shutdown)
    closed = []

    class H:
        def shutdown(self):
            closed.append(True)

    monkeypatch.setattr(setup, "_handle", H())
    api.stop_observability()
    assert closed == [True]


# ── 7. hooks contract: nothing raises into callers ──────────────────────────

def test_public_methods_never_raise_on_bad_input():
    m = WandbCampaignMetrics(wandb_module=FakeWandb(), url_check=lambda u: None)
    m.log("c", None)  # type: ignore[arg-type]
    m.log("c", ["x"])  # type: ignore[arg-type]
    m.log(None, {"x": 1.0})  # type: ignore[arg-type]
    m.service_log(None)  # type: ignore[arg-type]
    m.alert("t", "x", level=None)  # type: ignore[arg-type]
    m.alert(None, None, level=5)  # type: ignore[arg-type]
    m.campaign_started("c", None)  # type: ignore[arg-type]
    m.campaign_finished("c", None)  # type: ignore[arg-type]
    m.service_started(None, 5)  # type: ignore[arg-type]
    assert m.flush(5)


# ── 9. caller dicts are snapshotted at submit time ──────────────────────────

def test_caller_mutation_after_submit_is_not_exported():
    gate = threading.Event()

    class Slow(FakeWandb):
        def init(self, **kw):
            gate.wait(5)
            return super().init(**kw)

    sdk = Slow()
    m = WandbCampaignMetrics(wandb_module=sdk)
    cfg = {"environment": "production", "note": "before"}
    summary = {"headline": {"asr": 0.1}, "report_markdown": "ok"}
    m.campaign_started("c", cfg)
    m.campaign_finished("c", summary)
    cfg["note"] = "AFTER-MUTATION"
    cfg["secret_value"] = "leaks-later"
    summary["headline"]["asr"] = 99
    gate.set()
    assert m.flush(10)
    assert "AFTER-MUTATION" not in repr(sdk.kw) and "leaks-later" not in repr(sdk.kw)
    assert sdk.run.summary["asr"] == 0.1


# ── 3. run files never go in the CWD ────────────────────────────────────────

def test_default_directory_is_outside_cwd_and_conftest_sets_wandb_dir():
    m = WandbCampaignMetrics(wandb_module=FakeWandb())
    assert m.directory.startswith(tempfile.gettempdir())
    assert not os.path.abspath(m.directory).startswith(os.getcwd())
    assert os.environ["WANDB_DIR"].startswith(tempfile.gettempdir()) or "wandb" in os.environ["WANDB_DIR"]
    assert not os.path.exists(os.path.join(os.getcwd(), "wandb"))


def test_service_run_retries_after_backoff():
    class Flaky(FakeWandb):
        n = 0

        def init(self, **kw):
            Flaky.n += 1
            if Flaky.n == 1:
                raise ConnectionError("down")
            return super().init(**kw)

    sdk = Flaky()
    m = WandbCampaignMetrics(wandb_module=sdk, backoff_s=0.05)
    m.service_started("api")
    assert m.flush(5) and m.service_failed
    time.sleep(0.1)
    m.service_log({"a": 1.0})
    assert m.flush(5)
    assert not m.service_failed and sdk.run.logged


# ── keyed hashes ────────────────────────────────────────────────────────────

def test_same_input_different_keys_gives_different_hashes_and_is_stable():
    redact.configure_hash_key("key-one")
    a1, a2 = redact.hash_marker("123-45-6789"), redact.hash_marker("123-45-6789")
    redact.configure_hash_key("key-two")
    b = redact.hash_marker("123-45-6789")
    assert a1 == a2 and a1 != b
    import hashlib

    plain = hashlib.sha256(b"123-45-6789").hexdigest()[:16]
    assert plain not in a1 and plain not in b  # not a bare sha256


def test_no_key_emits_no_hash_anywhere():
    redact.configure_hash_key(None)
    assert redact.hash_marker("123456789") == "[REDACTED:text len=9]"
    assert redact.hash_suffix("123456789") == ""
    for out in (
        redact.preview("some free text 123 here"),
        redact.sanitize({"k": "free text value"})["k"],
        redact.safe_exception_message(ValueError("boom")),
        redact.redact_text("x " * 5000),
        redact.redact_long("word " * 4000),
    ):
        assert "hmac" not in out and "sha256" not in out
    assert redact.safe_exception_message(ValueError("boom")) == "ValueError [REDACTED:text len=4]"


# ── redact_long fails closed ────────────────────────────────────────────────

def test_redact_long_never_emits_unredacted_tail_for_huge_secret():
    secret = "Z" * 400_000
    text = "intro words " * 600 + "token=" + secret + " tail words"
    out = redact.redact_long(text)
    assert "ZZZZZZZZ" not in out
    assert "intro words" in out
    assert "tail words" not in out or "ZZZZ" not in out
