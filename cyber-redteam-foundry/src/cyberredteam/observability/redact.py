"""Redaction adapter for everything W&B / Weave exports.

Text goes through the WP6 redactor (``storage.v2.redaction.redact``) when it
is importable. If it is not (or it raises), the adapter FAILS CLOSED: the text
is replaced by ``[sha256:<16 hex> len=<n>]``, never exported raw.

``sanitize`` walks arbitrary structures, drops auth headers / secret-looking
keys / ``SecretStr`` values and turns free text into a redacted preview plus a
hash. Raw text is exported only when :func:`raw_export_allowed` is true
(``WANDB_EXPORT_RAW_EVIDENCE`` on AND environment == ``staging``).
"""

from __future__ import annotations

import contextvars
import dataclasses
import hashlib
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

_ID_LIKE = re.compile(r"^(?:[0-9a-fA-F]{8,64}|[0-9a-fA-F-]{36}|\[sha256:[0-9a-f]{16} len=\d+\])$")
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


def _sha16(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]


def hash_marker(text: str) -> str:
    return f"[sha256:{_sha16(text)} len={len(text)}]"


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
    try:
        from cyberredteam.storage.v2.redaction import redact

        out = str(redact(head).text)
    except Exception:  # unavailable or failing: never export raw
        return hash_marker(full) if fail_closed else head
    if len(full) > MAX_REDACT_CHARS:
        out += f" …[truncated {len(full) - MAX_REDACT_CHARS} chars {hash_marker(full)}]"
    return out


def preview(text: str | None, hashes: bool = True) -> str:
    """Redacted preview (<= PREVIEW_CHARS) plus a hash of the original text."""
    original = "" if text is None else str(text)
    if _ID_LIKE.match(original):
        return original  # ids and hashes pass through untouched
    red = redact_text(original)
    if red.startswith("[sha256:") and red.endswith("]"):
        return red  # fail-closed marker already carries hash and length
    if not hashes:
        return red[:PREVIEW_CHARS]
    return f"{red[:PREVIEW_CHARS]} {hash_marker(original)}"


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
        return f"{name}: {_sanitize_str(text, raw_export_allowed())}"
    except Exception:
        return name
