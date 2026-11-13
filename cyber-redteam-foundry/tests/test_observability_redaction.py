"""WP11: nothing secret or PII leaves the process through the trace hooks."""

import pytest
from pydantic import SecretStr

from cyberredteam.observability import hooks, redact
from cyberredteam.observability.weave_tracing import build_tracer

SECRET = "sk-live-SUPERSECRETVALUE123456"
BEARER = "Bearer abcdefghijklmnop.qrstuvwx.yz0123456789"
EMAIL = "alice.example@corp-example.com"


@pytest.fixture(autouse=True)
def _reset():
    redact.configure_raw_export(False)
    redact._known_secrets.clear()
    yield
    redact.configure_raw_export(False)
    redact._known_secrets.clear()


def _inputs():
    return {
        "self": object(),
        "api_key": SecretStr(SECRET),
        "headers": {"Authorization": BEARER, "X-Api-Key": SECRET, "Accept": "json"},
        "message": f"contact me at {EMAIL} with {BEARER} and key {SECRET}",
        "tokens_in": 12,
    }


def test_inputs_export_no_raw_secret_bearer_header_or_email():
    redact.register_secret(SECRET)
    out = redact.sanitize_inputs(_inputs())
    text = repr(out)
    for leaked in (SECRET, "abcdefghijklmnop", EMAIL, "alice.example"):
        assert leaked not in text
    assert out["headers"]["Authorization"] == "[REDACTED:secret]"
    assert out["headers"]["X-Api-Key"] == "[REDACTED:secret]"
    assert out["api_key"] == "[REDACTED:secret]"
    assert out["tokens_in"] == 12  # counters are not mistaken for secrets
    assert "sha256:" in out["message"]  # preview carries a hash


def test_output_dataclasses_are_sanitized():
    from cyberredteam.transport.session_adapter import TurnResult

    out = redact.sanitize_output(TurnResult(response_text=f"mail {EMAIL}", http_status=200))
    assert EMAIL not in repr(out)
    assert out["http_status"] == 200


def test_fails_closed_without_redactor(monkeypatch):
    import sys

    monkeypatch.setitem(sys.modules, "cyberredteam.storage.v2.redaction", None)
    out = redact.redact_text("totally raw text")
    assert out.startswith("[sha256:") and "raw" not in out


def test_uses_real_wp6_redactor():
    out = redact.redact_text(f"mail {EMAIL}")
    assert EMAIL not in out and not out.startswith("[sha256:")


@pytest.mark.parametrize(
    "flag,env,raw",
    [(True, "staging", True), (True, "production", False), (False, "staging", False),
     (True, None, False)],
)
def test_raw_export_only_for_staging_with_flag(flag, env, raw):
    redact.configure_raw_export(flag)
    token = redact.set_environment(env) if env else None
    try:
        out = redact.sanitize({"text": "plain evidence", "authorization": "x"})
    finally:
        if token:
            redact.reset_environment(token)
    assert (out["text"] == "plain evidence") is raw
    assert out["authorization"] == "[REDACTED:secret]"  # never exported, even raw


def test_trace_op_returns_usable_functions_without_weave(monkeypatch):
    import sys

    monkeypatch.setitem(sys.modules, "weave", None)

    def f(a):
        return a + 1

    assert build_tracer()("x")(f)(1) == 2
    assert hooks.trace_op("noop")(f)(2) == 3  # default tracer is identity


def test_traced_op_runs_sync_and_async_and_propagates_errors():
    pytest.importorskip("weave")
    import asyncio

    tracer = build_tracer()

    @tracer("t.sync")
    def sync(x):
        return x * 2

    @tracer("t.async")
    async def acoro(x):
        return x * 3

    @tracer("t.err")
    def boom():
        raise ValueError("inner")

    assert sync(2) == 4
    assert asyncio.run(acoro(2)) == 6
    with pytest.raises(ValueError):
        boom()
    assert asyncio.iscoroutinefunction(acoro)
