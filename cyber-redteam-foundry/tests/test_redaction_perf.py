"""WP11 review: redaction must be linear on large unbroken inputs (no ReDoS)."""

import time

import pytest

from cyberredteam.storage.v2.redaction import redact

N = 100_000
CASES = {
    "no_spaces": "a" * N,
    "dotted_run": "a." * (N // 2),
    "domain_run": "x@" + "a." * (N // 2),
    "at_signs": "a@" * (N // 2),
    "dash_run_then_kv": "x-" * (N // 2) + "token=abcdef",
    "unclosed_quotes": 'token="' * (N // 7),
    "curl_spam": "curl " * (N // 5),
    "long_quoted": 'api_key="' + "b" * N,
    "keyword_spam": "password " * (N // 9),
    "scheme_run": "a.b-c+" * (N // 6),
}


@pytest.mark.parametrize("name", list(CASES))
def test_redaction_is_fast_on_pathological_input(name):
    start = time.perf_counter()
    redact(CASES[name])
    assert time.perf_counter() - start < 1.0


def test_long_local_part_email_is_still_masked():
    out = redact("mail " + "a" * 200 + "@example.com ok").text
    assert "example.com" not in out and "ok" in out


@pytest.mark.parametrize("n", [1999, 2001, 2500, 50_000])
def test_long_quoted_secret_values_are_still_redacted(n):
    secret = "A" * n
    for text in (f'{{"api_key": "{secret}", "x": 1}}', f"password='{secret}'",
                 f'api_key = "{secret}'):
        out = redact(text).text
        assert "AAAAAAAAAA" not in out, (n, text[:20])
    assert '"x": 1' in redact(f'{{"api_key": "{secret}", "x": 1}}').text


def test_empty_quoted_value_unchanged():
    assert redact('api_key=""').text == 'api_key=""'


def test_long_quoted_values_stay_linear():
    start = time.perf_counter()
    redact('api_key="' * 11_000)
    redact('password="' + "b" * 100_000)
    assert time.perf_counter() - start < 1.0
