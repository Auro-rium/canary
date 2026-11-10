"""Assemble SSE / NDJSON response bodies into chunks and full reply text."""

from __future__ import annotations

import json
from typing import Any

# Tried per chunk when ``response_path`` is unset or does not resolve in a chunk.
DELTA_FALLBACK_PATHS = (
    "choices.0.delta.content",
    "delta.content",
    "delta",
    "token",
    "content",
    "text",
    "response",
    "output",
)


class StreamParseError(ValueError):
    """The stream body is not valid for the declared streaming mode."""


def get_path(data: Any, path: str) -> Any:
    """Walk a dot path through dicts and lists (numeric segments index lists).

    Returns ``None`` when any segment is missing.
    """
    node = data
    for part in path.split("."):
        if isinstance(node, dict):
            if part not in node:
                return None
            node = node[part]
        elif isinstance(node, list):
            try:
                node = node[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return node


def parse_sse(body: bytes) -> list[Any]:
    """Return the ``data:`` payloads of an SSE stream (JSON-decoded when possible)."""
    text = body.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
    chunks: list[Any] = []
    for event in text.split("\n\n"):
        data_lines: list[str] = []
        for line in event.split("\n"):
            if line.startswith("data:"):
                value = line[5:]
                data_lines.append(value[1:] if value.startswith(" ") else value)
        if not data_lines:
            continue
        payload = "\n".join(data_lines)
        if payload.strip() == "[DONE]":
            break
        try:
            chunks.append(json.loads(payload))
        except (ValueError, RecursionError):
            chunks.append(payload)
    return chunks


def parse_ndjson(body: bytes) -> list[Any]:
    chunks: list[Any] = []
    for line in body.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            chunks.append(json.loads(line))
        except (ValueError, RecursionError) as exc:
            raise StreamParseError("invalid NDJSON line") from exc
    return chunks


def parse_stream(mode: str, body: bytes) -> list[Any]:
    if mode == "sse":
        return parse_sse(body)
    if mode == "ndjson":
        return parse_ndjson(body)
    raise ValueError(f"not a streaming mode: {mode}")


def _is_final_event(chunk: Any) -> bool:
    """Full-text summary events (``*.done``, ``*.completed``) that repeat the deltas."""
    if not isinstance(chunk, dict):
        return False
    kind = chunk.get("type") or chunk.get("event")
    return isinstance(kind, str) and kind.endswith((".done", ".completed", "_done", "done"))


def chunk_text(chunk: Any, response_path: str | None) -> str | None:
    """Text carried by one chunk, or ``None`` if it carries none.

    With ``response_path`` only that path is consulted; otherwise the first
    fallback path that yields text.
    """
    if isinstance(chunk, str):
        return chunk
    paths = [response_path] if response_path else DELTA_FALLBACK_PATHS
    for path in paths:
        value = get_path(chunk, path)
        if isinstance(value, str):
            return value
    return None


def _lock_path(chunks: list[Any]) -> str | None:
    """The fallback path used for the whole stream: the first one that yields
    text on a non-final chunk (final chunks only if nothing else does)."""
    for candidates in ([c for c in chunks if not _is_final_event(c)], chunks):
        for chunk in candidates:
            if isinstance(chunk, str):
                continue
            for path in DELTA_FALLBACK_PATHS:
                if isinstance(get_path(chunk, path), str):
                    return path
    return None


def assemble_text(chunks: list[Any], response_path: str | None) -> str | None:
    """Concatenate per-chunk text; ``None`` if no chunk carried any.

    Without ``response_path`` the stream locks onto one fallback path and
    ignores final full-text events, so Responses-API style streams
    (deltas then ``done`` with the whole text) are not duplicated.
    """
    path = response_path or _lock_path(chunks)
    parts: list[str] = []
    for chunk in chunks:
        if isinstance(chunk, str):
            parts.append(chunk)
        elif path:
            value = get_path(chunk, path)
            if isinstance(value, str) and (response_path or not _is_final_event(chunk) or not parts):
                parts.append(value)
    return "".join(parts) if parts else None
