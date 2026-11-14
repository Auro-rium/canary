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
