from __future__ import annotations

from cyberredteam.security.tokens import (
    hash_verification_token,
    issue_project_token,
    issue_verification_token,
    parse_project_token,
    verify_project_token,
    verify_verification_token,
)


def test_verification_token_is_hashable_and_verifiable() -> None:
    token = issue_verification_token()
    digest = hash_verification_token(token, pepper="application-pepper")

    assert verify_verification_token(token, digest, pepper="application-pepper")
    assert not verify_verification_token("wrong-token", digest, pepper="application-pepper")
    assert not verify_verification_token(token, digest, pepper="different-pepper")


def test_project_token_exposes_prefix_but_persists_only_digest() -> None:
    issued = issue_project_token(pepper="application-pepper")

    parsed = parse_project_token(issued.token)
    assert parsed is not None
    assert parsed[0] == issued.lookup_prefix
    assert issued.token not in issued.token_hash
    assert verify_project_token(issued.token, issued.token_hash, pepper="application-pepper")
    assert not verify_project_token(issued.token, issued.token_hash, pepper="different-pepper")


def test_malformed_project_token_cannot_be_verified() -> None:
    issued = issue_project_token()

    assert parse_project_token("canary_project_missing-secret") is None
    assert parse_project_token("not-a-project-token") is None
    assert not verify_project_token("canary_project_missing-secret", issued.token_hash)
