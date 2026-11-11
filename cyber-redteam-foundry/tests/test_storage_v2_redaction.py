"""Redaction: pure function, no I/O."""

from cyberredteam.storage.v2.redaction import redact


def test_clean_text_untouched():
    r = redact("The weather is nice. Call me maybe tomorrow at noon.")
    assert r.text == "The weather is nice. Call me maybe tomorrow at noon."
    assert r.hits == []


def test_empty_and_none():
    assert redact("").text == ""
    assert redact(None).hits == []


def test_api_keys():
    r = redact("key sk-abcdefghijklmnopqrstuvwx and AKIAIOSFODNN7EXAMPLE and ghp_" + "a" * 36)
    assert "sk-abcdef" not in r.text and "AKIAIOSFODNN7EXAMPLE" not in r.text
    assert r.hits == ["api_key"]


def test_bearer_header():
    r = redact("Authorization: Bearer abc123def456ghi789")
    assert "abc123def456ghi789" not in r.text
    assert "Bearer [REDACTED:bearer_token]" in r.text
    assert "bearer_token" in r.hits


def test_jwt():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.SflKxwRJSMeKKF2QT4fwpM"
    r = redact(f"token was {jwt} ok")
    assert jwt not in r.text and r.hits == ["jwt"]


def test_key_value_secret():
    r = redact('password: hunter2hunter2 and api_key="zzzz-1234-yyyy"')
    assert "hunter2hunter2" not in r.text and "zzzz-1234-yyyy" not in r.text
    assert r.hits == ["secret"]


def test_email_phone_ssn():
    r = redact("mail jane.doe@example.co.uk, call (415) 555-2671 or +1 415-555-2671, ssn 123-45-6789")
    assert "jane.doe" not in r.text and "555-2671" not in r.text and "123-45-6789" not in r.text
    assert set(r.hits) == {"email", "phone", "ssn"}


def test_credit_card_luhn():
    good = redact("card 4111 1111 1111 1111 thanks")
    assert "4111" not in good.text and good.hits == ["credit_card"]
    bad = redact("order number 4111 1111 1111 1112")  # fails Luhn, not a card
    assert "credit_card" not in bad.hits
    assert "4111 1111 1111 1112" in bad.text


def test_canary_values_longest_first_and_reported():
    r = redact("leak CANARY-ABC-123 and CANARY-ABC", canary_values=["CANARY-ABC", "CANARY-ABC-123"])
    assert "CANARY" not in r.text
    assert r.hits == ["canary"]


def test_hits_deduplicated_in_order():
    r = redact("a@b.io then c@d.io, ssn 123-45-6789")
    assert r.hits == ["email", "ssn"]


def test_idempotent():
    once = redact("a@b.io 123-45-6789").text
    assert redact(once).text == once


def test_json_quoted_keys():
    r = redact('{"api_key": "abcd1234efgh", "password":"hunter2hunter2", "client_secret":"s3cr3tvalue"}')
    for leaked in ("abcd1234efgh", "hunter2hunter2", "s3cr3tvalue"):
        assert leaked not in r.text
    assert r.hits == ["secret"]
    assert redact('{"max_tokens": 1000}').hits == []


def test_pem_private_key():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\nabcdef\n-----END RSA PRIVATE KEY-----"
    r = redact(f"here: {pem} done")
    assert "MIIEow" not in r.text and r.hits == ["private_key"] and r.text.endswith("done")
    assert "MIIEow" not in redact("-----BEGIN PRIVATE KEY-----\nMIIEow").text  # truncated block


def test_basic_auth_header():
    r = redact("Authorization: Basic dXNlcjpwYXNzd29yZA==")
    assert "dXNlcjpw" not in r.text and r.hits == ["basic_auth"]
    assert redact("a basic understanding of things").hits == []


def test_aws_credentials():
    r = redact("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY and ASIAIOSFODNN7EXAMPLE")
    assert "wJalrXUtnFEMI" not in r.text and "ASIAIOSFODNN7" not in r.text
    assert set(r.hits) == {"secret", "api_key"}
    assert "wJalr" not in redact("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY").text


def test_url_credentials():
    r = redact("connect postgres://admin:s3cretpw@db.internal:5432/app now")
    assert "s3cretpw" not in r.text and "admin" not in r.text and r.hits == ["url_credentials"]
    assert "db.internal" in r.text
    assert redact("https://example.com/path").text == "https://example.com/path"
