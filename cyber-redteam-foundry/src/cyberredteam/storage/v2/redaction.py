"""Secret and PII redaction. Pure function, no I/O.

``redact(text, canary_values=...)`` returns ``RedactionResult(text, hits)``:
the masked text and the ordered, de-duplicated list of hit types.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import NamedTuple


class RedactionResult(NamedTuple):
    text: str
    hits: list[str]


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


_PEM = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?"
    r"(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|\Z)"
)
# scheme://userinfo@host where userinfo has a colon; the password may contain '@'
# (match up to the last '@' of the authority).
_URL_CREDS = re.compile(r"\b([A-Za-z][A-Za-z0-9+.-]{0,31}://)[^\s/?#:@]*:[^\s/?#]*@")
_BASIC = re.compile(
    r"(?i)(authorization[\\\"']{0,2}\s*[:=]\s*[\\\"']{0,2}basic\s+)[A-Za-z0-9+/=]{6,}"
)
_COOKIE = re.compile(
    r"(?i)\b((?:set-)?cookie[\\\"']{0,2}\s*:\s*)(?:\\?\"[^\"\\]*\\?\"|'[^']*'"
    # A missing closing quote means: redact to the end of the line.
    r"|\\?\"[^\r\n]*|'[^\r\n]*"
    # Bare value: must not start with whitespace or a quote.
    r"|[^\s\"'][^\r\n\"]*)"
)
_CURL_USER = re.compile(
    r"(?i)(\bcurl\b[^\n]{0,500}?\s(?:-u|--user)[ =]+)(?:\"[^\"]*\"|'[^']*'"
    r"|\"[^\n]*|'[^\n]*|\S+)"
)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}")
_BEARER = re.compile(r"(?i)\b(bearer)(\s+)[A-Za-z0-9._~+/=-]{8,}")
_KEY_PATTERNS = re.compile(
    r"\b(?:"
    r"sk-ant-[A-Za-z0-9_-]{16,}|sk-[A-Za-z0-9_-]{20,}|sk_(?:live|test)_[A-Za-z0-9]{16,}"
    r"|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}"
    r"|(?:AKIA|ASIA)[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|xox[abprs]-[A-Za-z0-9-]{10,}"
    r")\b"
)
_KV_SECRET = re.compile(
    r"(?i)((?:api[_-]?key|secret[_-]?access[_-]?key|secret(?:[_-]?key)?|access[_-]?token"
    r"|auth[_-]?token|token|password|passwd|passphrase|pwd|client[_-]?secret)"
    r"(?:\\?[\"'])?\s*[:=]\s*)"
    r"(?:\\?([\"'])(?:(?!\\?\2)[^\n]){1,2000}?\\?\2"
    # Linear fallback for quoted values longer than 2000 chars or unterminated ones:
    # redact up to the closing quote (or end of line).
    r"|\\?([\"'])(?:(?!\\?\3)[^\n])+(?:\\?\3)?"
    r"|[^\"'\s,;}\]\\]{4,})"
)
# Lookbehind (not \b): a match can only start at the beginning of a local-part run,
# so a long run without '@' is scanned once, not once per start position.
_EMAIL = re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b")
_SSN = re.compile(r"(?<![\d-])\d{3}-\d{2}-\d{4}(?![\d-])")
_CARD = re.compile(r"(?<![\d])(?:\d[ -]?){12,18}\d(?![\d])")
_PHONE = re.compile(
    r"(?<![\w-])(?:\+\d{1,3}[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4}(?![\w-])"
)


def redact(text: str | None, canary_values: Iterable[str] = ()) -> RedactionResult:
    """Mask secrets and PII in ``text``; ``canary_values`` are exact strings to mask."""
    if not text:
        return RedactionResult(text or "", [])
    hits: list[str] = []

    def note(kind: str) -> str:
        if kind not in hits:
            hits.append(kind)
        return f"[REDACTED:{kind}]"

    out = text
    for value in sorted({v for v in canary_values if v}, key=len, reverse=True):
        if value in out:
            out = out.replace(value, note("canary"))
    out = _PEM.sub(lambda m: note("private_key"), out)
    out = _COOKIE.sub(lambda m: f"{m.group(1)}{note('cookie')}", out)
    out = _CURL_USER.sub(lambda m: f"{m.group(1)}{note('curl_credentials')}", out)
    out = _URL_CREDS.sub(lambda m: f"{m.group(1)}{note('url_credentials')}@", out)
    out = _BASIC.sub(lambda m: f"{m.group(1)}{note('basic_auth')}", out)
    out = _JWT.sub(lambda m: note("jwt"), out)
    out = _BEARER.sub(lambda m: f"{m.group(1)}{m.group(2)}{note('bearer_token')}", out)
    out = _KEY_PATTERNS.sub(lambda m: note("api_key"), out)
    out = _KV_SECRET.sub(lambda m: f"{m.group(1)}{note('secret')}", out)
    out = _EMAIL.sub(lambda m: note("email"), out)
    out = _SSN.sub(lambda m: note("ssn"), out)

    def _card(m: re.Match) -> str:
        digits = re.sub(r"[ -]", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            return note("credit_card")
        return m.group(0)

    out = _CARD.sub(_card, out)
    out = _PHONE.sub(lambda m: note("phone"), out)
    return RedactionResult(out, hits)
