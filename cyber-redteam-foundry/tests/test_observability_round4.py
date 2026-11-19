"""WP11 round-4 regressions: secret-looking keys, curl/auth/cookie forms, provider keys,
relative-URL query strings and a failing weave.attributes context manager."""

import time
from types import SimpleNamespace

import pytest
from test_observability_metrics import FakeWandb

from cyberredteam.observability import redact, weave_tracing
from cyberredteam.observability.wandb_metrics import WandbCampaignMetrics
from cyberredteam.storage.v2.redaction import redact as storage_redact


@pytest.fixture(autouse=True)
def _clean():
    redact.reset_state()
    yield
    redact.reset_state()


def _both(text: str) -> tuple[str, str]:
    return storage_redact(text).text, redact.redact_text(text)


# ── 1. mapping keys are never exported verbatim when they carry secrets ─────

@pytest.mark.parametrize("key_hash", [None, "k" * 32])
def test_secret_bearing_keys_are_replaced_by_markers(key_hash):
    redact.configure_hash_key(key_hash)
    out = redact.sanitize({"token=SECRET": 1, "Cookie: s=SECRET": 1,
                           "token=SECRETINKEY": "v", "Authorization: Bearer abcdefgh12345": 1})
    assert "SECRET" not in repr(out) and "abcdefgh12345" not in repr(out)
    assert len(out) == 4  # unkeyed markers are de-duplicated, no entry lost


def test_plain_identifier_keys_survive_and_long_or_spaced_keys_do_not():
    out = redact.sanitize({"turns_total": 1, "model.name": "x", "a" * 65: 2, "has space": 3})
    assert out["turns_total"] == 1 and "model.name" in out
    assert "a" * 65 not in out and "has space" not in out
    # identifier-shaped keys that a redactor would rewrite are hashed too
    assert "sk-proj-abcdefghijklmnopqrstuvwxyz0123" not in repr(
        redact.sanitize({"sk-proj-abcdefghijklmnopqrstuvwxyz0123": 1}))


def test_nested_and_secret_branch_keys_are_safe():
    out = redact.sanitize({"outer": {"password=SECRETNESTED": "x", "ok": {"Cookie: SECRET2": 1}}})
    assert "SECRET" not in repr(out)


def test_wandb_summary_and_findings_columns_use_safe_keys():
    sdk = FakeWandb()
    m = WandbCampaignMetrics(wandb_module=sdk)
    m.campaign_started("c", {"environment": "production"})
    m.campaign_finished("c", {
        "token=SECRETSUMMARY": 3,
        "asr": 0.5,
        "findings": [{"Cookie: s=SECRETCOL": "v", "severity": "high"}],
    })
    assert m.flush(5)
    run = sdk.run
    assert "SECRET" not in repr(run.summary) and run.summary["asr"] == 0.5
    tables = {k: v for d, _ in run.logged for k, v in d.items()}
    cols = tables["findings"].columns
    assert "SECRET" not in repr(cols) and "severity" in cols
    assert len(cols) == len(set(cols))


def test_safe_key_dedup_columns_stay_distinct():
    sdk = FakeWandb()
    m = WandbCampaignMetrics(wandb_module=sdk)
    m.campaign_started("c", {})
    m.campaign_finished("c", {"findings": [{"token=AAAAA": 1, "token=BBBBB": 2}]})
    assert m.flush(5)
    tables = {k: v for d, _ in sdk.run.logged for k, v in d.items()}
    cols = tables["findings"].columns
    assert len(cols) == 2 and len(set(cols)) == 2 and "AAAAA" not in repr(cols)


# ── 2. curl -u / --user anywhere ────────────────────────────────────────────

@pytest.mark.parametrize("text", [
    "curl https://api.x.com/v1 \\\n  -u admin:SECRETMULTI \\\n  -d x=1",
    "curl -uadmin:SECRETNOSPACE https://x",
    "curl -X POST https://x -d '" + "a b" * 300 + "' -u admin:SECRETFAR",
    "curl https://x --user=admin:SECRETEQ",
    'curl https://x --user "admin:SECRET QUOTED"',
    "curl https://x -U proxyuser:SECRETPROXY",
])
def test_curl_user_variants(text):
    for out in _both(text):
        assert "SECRET" not in out, out


def test_curl_user_agent_is_not_mangled():
    out = storage_redact('curl --user-agent "Mozilla/5.0" https://x').text
    assert out == 'curl --user-agent "Mozilla/5.0" https://x'


def test_curl_flag_regexes_stay_linear():
    start = time.perf_counter()
    storage_redact(' -u "' * 20_000)
    storage_redact(" -b '" * 20_000)
    storage_redact(" -u" * 30_000)
    storage_redact("Authorization: " * 10_000)
    storage_redact('"Authorization: x' * 8_000)
    assert time.perf_counter() - start < 1.0


# ── 3. curl -b / --cookie ───────────────────────────────────────────────────

@pytest.mark.parametrize("text", [
    'curl -b "session=SECRETCOOKIE1" https://x',
    "curl --cookie session=SECRETCOOKIE2 https://x",
    "curl --cookie='session=SECRETCOOKIE3' https://x",
    "curl -b 'session=SECRETCOOKIE4",
])
def test_curl_cookie_flag(text):
    r = storage_redact(text)
    assert "SECRETCOOKIE" not in r.text and "cookie" in r.hits
    assert "SECRETCOOKIE" not in redact.redact_text(text)


def test_curl_cookie_jar_flag_is_not_a_cookie():
    assert storage_redact("curl --cookie-jar jar.txt https://x").hits == []


# ── 4. generic (Proxy-)Authorization header ────────────────────────────────

@pytest.mark.parametrize("text", [
    "Authorization: Token SECRETTOKEN",
    "Authorization: SECRETRAWKEY",
    'Authorization: Bearer "SECRETQUOTED',
    "Authorization: Bearer SECRT",
    "Proxy-Authorization: Negotiate SECRETNEG",
    "curl -H 'Authorization: Token SECRETTOKENX' https://x",
    'curl -H "Authorization: SECRETRAWKEY" https://x',
    'Authorization: Digest username="a", response="SECRETDIGEST"',
    '{"Authorization": "Token SECRETJSON", "x": 1}',
])
def test_any_authorization_scheme_is_redacted(text):
    for out in _both(text):
        assert "SECRET" not in out, out


def test_authorization_redaction_stops_at_enclosing_quote():
    out = storage_redact("curl -H 'Authorization: Token SECRETX' https://keep.example/x").text
    assert out == "curl -H 'Authorization: [REDACTED:authorization]' https://keep.example/x"
    out = storage_redact('{"Authorization": "Token SECRETJSON", "x": 1}').text
    assert '"x": 1' in out and "SECRET" not in out


def test_scheme_specific_auth_rules_keep_their_output():
    r = storage_redact("Authorization: Bearer abc123def456ghi789")
    assert "Bearer [REDACTED:bearer_token]" in r.text and r.hits == ["bearer_token"]
    assert storage_redact("Authorization: Basic dXNlcjpwYXNzd29yZA==").hits == ["basic_auth"]
    assert storage_redact("Authorization:").hits == []


@pytest.mark.parametrize("text", ["Bearer SECRET", "bearer=SECRETEQ", "bearer: SECRETCOLON"])
def test_short_and_assigned_bearer_tokens(text):
    assert "SECRET" not in storage_redact(text).text


# ── 5. provider keys, Azure header, URLs ───────────────────────────────────

@pytest.mark.parametrize("text", [
    "hf_abcdefghijklmnopqrstuvwxyzABCDEF",
    "token glpat-abcdefghijklmnopqrst here",
    'curl -H "Ocp-Apim-Subscription-Key: SECRETAZ2" https://x',
    "Ocp-Apim-Subscription-Key: SECRETAZ3",
    "https://hooks.slack.com/services/T00000000/B00000000/SECRETSLACKXXXXXXXXXXXX",
])
def test_provider_keys_and_headers(text):
    for out in _both(text):
        assert "SECRET" not in out and "abcdefghijklmnopqrst" not in out, out


@pytest.mark.parametrize("text", [
    "HTTPS://API.X.COM/v1?apikey=SECRETUP",
    "wss://stream.x.com/ws?token=SECRETWSS",
    "ftp://files.x.com/a?x=SECRETFTP",
    "/v1/items?key=SECRETPATHKEY",
    "/v1/items?sig=SECRETSIG&se=2025",
    "?sig=SECRETBARE",
    "GET /v1/data?foo=1&X-Amz-Signature=SECRETAMZ HTTP/1.1",
])
def test_url_query_strings(text):
    assert "SECRET" not in redact.mask_known(text)
    assert "SECRET" not in redact.redact_text(text)


def test_relative_query_keeps_non_secret_params():
    assert redact.mask_known("/v1/items?sig=SECRETSIG&se=2025&page=2") == (
        "/v1/items?sig=[REDACTED:query]&se=2025&page=2")


@pytest.mark.parametrize("text", [
    "My SSN is 123 45 6789",
    "postgres://user:pa SECRETss@host/db",
    'Cookie: "a" session=SECRETafterquote',
    "Cookie=session=SECRETeq",
])
def test_remaining_probe_forms(text):
    for out in _both(text):
        assert "SECRET" not in out and "6789" not in out, out


def test_cookie_json_value_does_not_swallow_following_fields():
    out = storage_redact('{"Cookie": "a=SECRET", "keep": 1}').text
    assert "SECRET" not in out and '"keep": 1' in out


# ── 6. weave.attributes enter/exit failures never reach the caller ─────────

class _BoomCM:
    def __init__(self, on):
        self.on = on

    def __enter__(self):
        if self.on == "enter":
            raise RuntimeError("enter boom")
        return self

    def __exit__(self, *exc):
        if self.on == "exit":
            raise RuntimeError("exit boom")
        return False


@pytest.mark.parametrize("on", ["build", "enter", "exit"])
def test_trace_attributes_survives_failing_weave_cm(monkeypatch, on):
    def attributes(_attrs):
        if on == "build":
            raise RuntimeError("build boom")
        return _BoomCM(on)

    monkeypatch.setattr(weave_tracing, "_weave", lambda: SimpleNamespace(attributes=attributes))
    monkeypatch.setattr(weave_tracing, "_initialized", True)
    ran = []
    with weave_tracing.trace_attributes(campaign_id="c1", environment="staging"):
        ran.append(redact.current_environment())
    assert ran == ["staging"]
    assert redact.current_environment() == "production"  # environment token restored


def test_trace_attributes_propagates_body_exception_only(monkeypatch):
    monkeypatch.setattr(weave_tracing, "_weave",
                        lambda: SimpleNamespace(attributes=lambda a: _BoomCM("exit")))
    monkeypatch.setattr(weave_tracing, "_initialized", True)
    with pytest.raises(ValueError, match="body"):
        with weave_tracing.trace_attributes(campaign_id="c1"):
            raise ValueError("body")


# ── review follow-ups: marker-shaped keys, linear URL-query masking ─────────

@pytest.mark.parametrize("key", [
    "[REDACTED:text len=1]#token=SECRET",
    "[hmac:0123456789abcdef len=3]#Cookie: s=SECRET",
    "[REDACTED:text len=1]#4111111111111111",
])
def test_marker_prefixed_keys_are_not_passed_through(key):
    assert "SECRET" not in repr(redact.sanitize({key: 1}))
    assert redact.safe_key(key) != key
    sdk = FakeWandb()
    m = WandbCampaignMetrics(wandb_module=sdk)
    m.campaign_started("c", {})
    m.campaign_finished("c", {key: 7, "findings": [{key: "v"}]})
    assert m.flush(5)
    tables = {k: v for d, _ in sdk.run.logged for k, v in d.items()}
    assert key not in repr(sdk.run.summary) and key not in repr(tables["findings"].columns)


def test_deduplicated_marker_keys_still_pass():
    assert redact.safe_key("[REDACTED:text len=5]#1") == "[REDACTED:text len=5]#1"
    assert redact.safe_key("[hmac:0123456789abcdef len=3]#12") == "[hmac:0123456789abcdef len=3]#12"


def test_url_query_masking_is_linear():
    start = time.perf_counter()
    redact.mask_known("a://" * 25_000)
    redact.mask_known("http://" * 25_000)
    redact.mask_known("?a=b&" * 40_000)
    redact.redact_long("a://" * 25_000)
    assert time.perf_counter() - start < 1.0


@pytest.mark.parametrize("text", [
    '"https://api.x.com/v1?api_key=SECRETQ"',
    "curl https://api.x.com/v1?api_key=SECRETQ&x=1",
    "url=https://x.com/a?q=SECRETQ",
    "[l](https://x.com/a?q=SECRETQ)",
])
def test_url_query_lead_ins_still_masked(text):
    assert "SECRETQ" not in redact.mask_known(text)
