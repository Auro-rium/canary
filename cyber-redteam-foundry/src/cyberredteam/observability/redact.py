"""Redaction adapter for everything W&B / Weave exports.

Text goes through the WP6 redactor (``storage.v2.redaction.redact``) when it
is importable. If it is not (or it raises), the adapter FAILS CLOSED: the text
is replaced by ``[hmac:<16 hex> len=<n>]`` (keyed; ``[REDACTED:text len=<n>]`` when no
key is configured), never exported raw.

``sanitize`` walks arbitrary structures, drops auth headers / secret-looking
keys / ``SecretStr`` values and turns free text into a redacted preview plus a
hash. Raw text is exported only when :func:`raw_export_allowed` is true
(``WANDB_EXPORT_RAW_EVIDENCE`` on AND environment == ``staging``).
"""

from __future__ import annotations

import contextvars
import dataclasses
import hashlib
import hmac
import logging
import re
import threading
from collections.abc import Mapping
from enum import Enum
from typing import Any

from pydantic import BaseModel, SecretBytes, SecretStr

logger = logging.getLogger(__name__)

PREVIEW_CHARS = 200
MAX_REDACT_CHARS = 4096  # redactor sees a bounded prefix; the hash covers everything
_MAX_DEPTH = 6
_MAX_ITEMS = 50

_SECRET_KEY = re.compile(
    r"(authorization|api[-_]?key|apikey|secret|token(?!s)|password|passwd|cookie|credential|"
    r"auth[-_]?header|x-api|bearer|private[-_]?key|session[-_]?id|[-_]key$)",
    re.IGNORECASE,
)

# Only our own hash marker passes through unredacted. Hex/digit strings are NOT exempt:
# they may be API keys, card numbers, SSNs or phone numbers.
_OWN_MARKER = re.compile(r"^\[(?:hmac:[0-9a-f]{16}|REDACTED:text) len=\d+\]$")
# Long hex strings and long digit runs are masked even where the WP6 redactor has no rule.
_WS = re.compile(r"\s")
_EXTRA_TOKEN = re.compile(r"(?<![\w-])(?:[0-9a-fA-F]{20,}|\d{9,}|"
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?![\w-])")
_URL_QUERY = re.compile(r"(https?://[^\s?#\"'<>]+)\?[^\s#\"'<>]*")

_known_secrets: set[str] = set()
_lock = threading.Lock()
_flag_raw = False
_environment: contextvars.ContextVar[str] = contextvars.ContextVar(
    "canary_obs_environment", default="production"
)


def register_secret(value: str | None) -> None:
    """Mask this exact string in every future export (defence in depth)."""
    if value and len(value) >= 6:
        with _lock:
            _known_secrets.add(value)


def configure_raw_export(enabled: bool) -> None:
    global _flag_raw
    _flag_raw = bool(enabled)


def set_environment(environment: str | None) -> contextvars.Token:
    """Set the target environment for this context (default: production)."""
    return _environment.set((environment or "production").lower())


def current_environment() -> str:
    return _environment.get()


def raw_export_allowed(environment: str | None = None) -> bool:
    env = (environment or current_environment()).lower()
    return _flag_raw and env == "staging"


_hash_key: bytes | None = None
_HASH_LABEL = b"canary-observability-hash-v1"


def configure_hash_key(secret: str | None) -> None:
    """Derive the per-deployment HMAC key from CANARY_ENCRYPTION_KEY (domain-separated).

    With no key, no hash is ever emitted (unkeyed hashes of low-entropy values such
    as SSNs or phone numbers are brute-forceable). Stable for a given deployment.
    """
    global _hash_key
    _hash_key = hmac.new(secret.encode(), _HASH_LABEL, hashlib.sha256).digest() if secret else None


def _mac16(text: str) -> str | None:
    if _hash_key is None:
        return None
    return hmac.new(_hash_key, text.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:16]


def hash_marker(text: str) -> str:
    """Keyed marker for ``text``; length-only ``[REDACTED:text len=N]`` without a key."""
    mac = _mac16(text)
    if mac is None:
        return f"[REDACTED:text len={len(text)}]"
    return f"[hmac:{mac} len={len(text)}]"


def hash_suffix(text: str) -> str:
    """`` [hmac:...]`` correlation suffix, or "" when no key is configured."""
    mac = _mac16(text)
    return "" if mac is None else f" [hmac:{mac} len={len(text)}]"


def _is_marker(text: str) -> bool:
    return bool(_OWN_MARKER.match(text))


def _mask_known(text: str) -> str:
    with _lock:
        secrets = sorted(_known_secrets, key=len, reverse=True)
    for s in secrets:
        if s in text:
            text = text.replace(s, "[REDACTED:secret]")
    return text


def mask_known(text: str) -> str:
    """Exact-secret masking plus URL query-string stripping (no regex redactor)."""
    return _URL_QUERY.sub(r"\1?[REDACTED:query]", _mask_known(text))


def _redact_core(piece: str) -> str | None:
    """Run the WP6 redactor (+ token masking) on ``piece``; None if unavailable."""
    try:
        from cyberredteam.storage.v2.redaction import redact

        return _EXTRA_TOKEN.sub("[REDACTED:token]", str(redact(piece).text))
    except Exception:
        return None


def redact_text(text: str | None, fail_closed: bool = True) -> str:
    """Redact ``text`` via the WP6 redactor, or fail closed to a hash marker.

    Only the first MAX_REDACT_CHARS are passed to the redactor (bounded cost);
    the remainder is dropped and replaced by a marker whose hash covers the full
    text. ``fail_closed=False`` (operator alert text, which carries no evidence
    by contract) falls back to exact-secret masking instead of a hash.
    """
    if not text:
        return ""
    full = str(text)
    head = mask_known(full[:MAX_REDACT_CHARS])
    out = _redact_core(head)
    if out is None:  # unavailable or failing: never export raw
        return hash_marker(full) if fail_closed else head
    if len(full) > MAX_REDACT_CHARS:
        out += f" …[truncated {len(full) - MAX_REDACT_CHARS} chars{hash_suffix(full)}]"
    return out


def preview(text: str | None, hashes: bool = True) -> str:
    """Redacted preview (<= PREVIEW_CHARS) plus a hash of the original text."""
    original = "" if text is None else str(text)
    masked = _mask_known(original)  # known secrets first, always
    if _OWN_MARKER.match(masked):
        return masked
    red = redact_text(original)
    if _is_marker(red):
        return red  # fail-closed marker already carries length (and keyed hash)
    if not hashes:
        return red[:PREVIEW_CHARS]
    return f"{red[:PREVIEW_CHARS]}{hash_suffix(original)}"


def _sanitize_str(text: str, raw: bool, hashes: bool = True) -> str:
    return mask_known(text) if raw else preview(text, hashes)


def sanitize(obj: Any, raw: bool | None = None, hashes: bool = True) -> Any:
    """Return a JSON-safe, redacted copy of ``obj``. Never raises.

    ``hashes=False`` drops the per-string hash suffix (config / table cells
    where readability matters); text is still redacted and truncated.
    """
    try:
        if raw is None:
            raw = raw_export_allowed()
        return _sanitize(obj, raw, 0, hashes)
    except Exception:
        return f"<unserializable {type(obj).__name__}>"


def _sanitize(obj: Any, raw: bool, depth: int, hashes: bool = True) -> Any:
    if isinstance(obj, (SecretStr, SecretBytes)):
        return "[REDACTED:secret]"
    if obj is None or isinstance(obj, (bool, int, float)):
        return obj
    if isinstance(obj, str):
        return _sanitize_str(obj, raw, hashes)
    if isinstance(obj, bytes):
        return hash_marker(obj.decode("utf-8", "replace"))
    if isinstance(obj, Enum):
        return _sanitize(obj.value, raw, depth + 1, hashes)
    if type(obj).__name__ in ("Url", "HttpUrl", "AnyUrl", "AnyHttpUrl"):
        return _sanitize_str(str(obj), raw, hashes)
    if depth >= _MAX_DEPTH:
        return f"<{type(obj).__name__}>"
    nxt = depth + 1
    if isinstance(obj, Mapping):
        out: dict[str, Any] = {}
        for i, (k, v) in enumerate(obj.items()):
            if i >= _MAX_ITEMS:
                out["..."] = f"{len(obj) - _MAX_ITEMS} more"
                break
            key = str(k)
            if _SECRET_KEY.search(key):
                out[key] = "[REDACTED:secret]"
            else:
                out[redact_text(key, fail_closed=False)[:100]] = _sanitize(v, raw, nxt, hashes)
        return out
    if isinstance(obj, (list, tuple, set, frozenset)):
        items = list(obj)
        out_l = [_sanitize(v, raw, nxt, hashes) for v in items[:_MAX_ITEMS]]
        if len(items) > _MAX_ITEMS:
            out_l.append(f"... {len(items) - _MAX_ITEMS} more")
        return out_l
    if isinstance(obj, BaseModel):
        # LangChain messages / chat results and our own models: dump fields;
        # secrets are masked by the key filter and the SecretStr branch.
        fields = {n: getattr(obj, n, None) for n in type(obj).model_fields}
        fields["_type"] = type(obj).__name__
        return _sanitize(fields, raw, nxt, hashes)
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        fields = {f.name: getattr(obj, f.name, None) for f in dataclasses.fields(obj)}
        fields["_type"] = type(obj).__name__
        return _sanitize(fields, raw, nxt, hashes)
    return f"<{type(obj).__name__}>"


def reset_environment(token: contextvars.Token) -> None:
    _environment.reset(token)


def sanitize_inputs(inputs: dict[str, Any]) -> dict[str, Any]:
    """``weave.op(postprocess_inputs=...)`` hook."""
    out = sanitize(inputs)
    return out if isinstance(out, dict) else {"inputs": out}


def sanitize_output(output: Any) -> Any:
    """``weave.op(postprocess_output=...)`` hook."""
    return sanitize(output)


def register_target_secrets(target: Any) -> None:
    """Mask every credential of a ``TargetConfig`` in all future exports."""
    auth = getattr(target, "auth", None)
    if auth is None:
        return
    for name in type(auth).model_fields:
        value = getattr(auth, name, None)
        if isinstance(value, SecretStr):
            register_secret(value.get_secret_value())
        elif name in ("username", "client_id") and isinstance(value, str):
            register_secret(value)


def safe_exception_message(exc: BaseException) -> str:
    """Redacted description of an exception, safe to export (type + preview)."""
    name = type(exc).__name__
    try:
        text = str(exc)
        try:
            from pydantic import ValidationError

            if isinstance(exc, ValidationError):
                # str() embeds input_value=...; build the message without inputs.
                text = "; ".join(
                    f"{'.'.join(str(p) for p in e.get('loc', ()))}: {e.get('msg', '')}"
                    for e in exc.errors(
                        include_input=False, include_url=False, include_context=False
                    )
                )
        except Exception:
            pass
        if raw_export_allowed():
            return f"{name}: {_sanitize_str(text, True)}"
        # Free-text PII is not regex-detectable: class name + hash only by default.
        return f"{name} {hash_marker(text)}"
    except Exception:
        return name


def redact_long(text: str | None, chunk: int = MAX_REDACT_CHARS, overlap: int = 512,
                max_total: int = 4_000_000) -> str:
    """Redact a long document (report) in bounded chunks, keeping all of it.

    Chunk cut points are chosen at whitespace and VERIFIED over an overlap
    window: a cut is accepted only if redacting ``left+right`` equals redacting
    each side separately, so a secret straddling the boundary is never split.
    If no safe cut is found, that region is replaced by a hash marker (fail
    closed). Input beyond ``max_total`` chars is replaced by a hash marker.
    """
    if not text:
        return ""
    full = mask_known(str(text))
    n = len(full)
    if n <= chunk:
        return redact_text(full)  # bounded single piece
    if n > max_total:
        return redact_text(full[:chunk]) + f" …[truncated {n - chunk} chars{hash_suffix(full)}]"

    def red(piece: str) -> str:
        r = _redact_core(piece)
        return hash_marker(piece) if r is None else r

    out: list[str] = []
    pos = 0
    while pos < n:
        if n - pos <= chunk + overlap:
            out.append(red(full[pos:]))
            break
        cand, step, cut = pos + chunk, 256, None
        for _ in range(10):  # exponentially growing search: bounded work per chunk
            if cand >= n - overlap:  # near the end: redact the remainder as one piece
                cut = n
                break
            ws = _WS.search(full, cand, cand + 256)
            c = ws.start() if ws else cand
            # Compare against the WHOLE chunk so far (not just a short window): a
            # secret that began earlier in the chunk (e.g. a PEM block) is seen.
            left, right = full[pos:c], full[c:c + overlap]
            if red(left + right) == red(left) + red(right):
                cut = c
                break
            cand = c + step
            step *= 2
        if cut is None:
            # Fail closed: no verified-safe cut in the search window, so everything
            # from here to the end becomes one marker. No unredacted tail is emitted.
            out.append(hash_marker(full[pos:]))
            break
        out.append(red(full[pos:cut]))
        pos = cut
    return "".join(out)
