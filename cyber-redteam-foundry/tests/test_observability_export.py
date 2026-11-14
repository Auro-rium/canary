"""WP11 review regressions: the REAL Weave export path (real ``weave.init`` and
``WeaveClient`` behind a recording trace server) leaks no secret, PII or raw
exception text, and does not auto-patch LangChain."""

import asyncio

import httpx
import pytest
from observability_support import RecordingServer, install_recording_weave, teardown_weave
from pydantic import BaseModel

pytest.importorskip("weave")

from cyberredteam.llm.backboard import ChatBackboard  # noqa: E402
from cyberredteam.observability import redact, weave_tracing  # noqa: E402

SSN = "123-45-6789"
EMAIL = "carol.private@example-corp.com"
EVIDENCE = "EVIDENCE-LEAK-9f8e7d6c-patient-record"
BEARER = "Bearer abcdefghijklmnopqrstuvwxyz0123456789"


@pytest.fixture
def server(monkeypatch):
    srv = RecordingServer()
    install_recording_weave(monkeypatch, srv)
    redact.configure_raw_export(False)
    assert weave_tracing.init_tracing("ent", "proj") is True
    yield srv
    teardown_weave()
    redact._known_secrets.clear()


def _flush():
    from weave.trace.context import weave_client_context as wcc

    wcc.get_weave_client().finish()


def _model():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"content": f"reply with {EMAIL}", "status": "COMPLETED"})

    return ChatBackboard(api_key="sk-test-backboard-key-123456", transport=httpx.MockTransport(handler))


def test_invoke_creates_no_langchain_calls_and_exports_no_raw_prompt(server):
    redact.register_secret("sk-test-backboard-key-123456")
    _model().invoke(f"My SSN is {SSN}, mail {EMAIL}, auth {BEARER}")
    _flush()
    names = server.op_names()
    assert names, "expected the backboard ops to be traced"
    assert not any("langchain" in n.lower() for n in names), names
    text = server.payload_text()
    for leaked in (SSN, EMAIL, "abcdefghijklmnopqrstuvwxyz0123456789", "sk-test-backboard-key"):
        assert leaked not in text


def test_weave_init_disables_implicit_patching(monkeypatch):
    from weave.trace import settings as wsettings

    srv = RecordingServer()
    install_recording_weave(monkeypatch, srv)
    try:
        assert weave_tracing.init_tracing("ent", "proj")
        assert wsettings.should_implicitly_patch_integrations() is False
    finally:
        teardown_weave()


def test_sync_exception_is_exported_redacted_but_caller_gets_original(server):
    @weave_tracing.build_tracer()("t.boom")
    def boom():
        raise ValueError(f"bad record ssn {SSN} owner {EMAIL}")

    with pytest.raises(ValueError) as info:
        boom()
    assert SSN in str(info.value) and EMAIL in str(info.value)  # callers unchanged
    _flush()
    ends = [r for k, r in server.sent if k == "call_end"]
    assert ends and ends[0]["end"]["exception"]
    exported = server.payload_text()
    for leaked in (SSN, EMAIL):
        assert leaked not in exported


def test_async_exception_is_exported_redacted_but_caller_gets_original(server):
    @weave_tracing.build_tracer()("t.aboom")
    async def aboom():
        raise RuntimeError(f"{SSN} {EMAIL}")

    with pytest.raises(RuntimeError, match="123-45"):
        asyncio.run(aboom())
    _flush()
    exported = server.payload_text()
    assert SSN not in exported and EMAIL not in exported


def test_pydantic_validation_error_input_value_not_exported(server):
    class Model(BaseModel):
        count: int

    @weave_tracing.build_tracer()("t.validate")
    def validate():
        return Model(count=EVIDENCE)  # type: ignore[arg-type]

    from pydantic import ValidationError

    with pytest.raises(ValidationError) as info:
        validate()
    assert EVIDENCE in str(info.value)
    _flush()
    assert EVIDENCE not in server.payload_text()


def test_nested_ops_propagate_original_exception_type(server):
    tracer = weave_tracing.build_tracer()

    class Custom(Exception):
        pass

    @tracer("t.inner")
    def inner():
        raise Custom("x")

    @tracer("t.outer")
    def outer():
        try:
            inner()
        except Custom:
            return "caught"

    assert outer() == "caught"


def test_judge_vote_feedback_is_redacted(server):
    @weave_tracing.build_tracer()("t.judge")
    def judged():
        return weave_tracing.log_judge_vote(
            None, judge="j1", verdict="unsafe", rationale=f"leaked {SSN} to {EMAIL}"
        )

    judged()
    _flush()
    text = server.payload_text()
    assert SSN not in text and EMAIL not in text
