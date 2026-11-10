"""Verification tokens: entropy, hash-only storage, constant-time compare."""

import hmac

from cyberredteam.security import tokens


def test_tokens_are_unique_and_long():
    issued = {tokens.issue_verification_token() for _ in range(100)}
    assert len(issued) == 100
    for t in issued:
        assert t.startswith(tokens.TOKEN_PREFIX)
        assert len(t) - len(tokens.TOKEN_PREFIX) >= 43  # 32 random bytes, urlsafe-b64


def test_hash_is_not_the_token_and_verifies():
    t = tokens.issue_verification_token()
    h = tokens.hash_verification_token(t)
    assert t not in h
    assert len(h) == 64
    assert tokens.verify_verification_token(t, h)


def test_wrong_or_empty_candidate_rejected():
    t = tokens.issue_verification_token()
    h = tokens.hash_verification_token(t)
    assert not tokens.verify_verification_token(t + "x", h)
    assert not tokens.verify_verification_token("", h)
    assert not tokens.verify_verification_token(None, h)
    assert not tokens.verify_verification_token(t, "")
    assert not tokens.verify_verification_token(t, None)


def test_pepper_changes_digest():
    t = tokens.issue_verification_token()
    peppered = tokens.hash_verification_token(t, pepper="p")
    assert tokens.hash_verification_token(t) != peppered
    assert tokens.verify_verification_token(t, peppered, pepper="p")


def test_uses_constant_time_compare(monkeypatch):
    calls = []
    real = hmac.compare_digest
    monkeypatch.setattr(
        tokens.hmac, "compare_digest", lambda a, b: calls.append(1) or real(a, b)
    )
    t = tokens.issue_verification_token()
    assert tokens.verify_verification_token(t, tokens.hash_verification_token(t))
    assert calls
