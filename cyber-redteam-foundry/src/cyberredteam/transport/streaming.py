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
        except ValueError:
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
        except ValueError as exc:
            raise StreamParseError("invalid NDJSON line") from exc
    return chunks


def parse_stream(mode: str, body: bytes) -> list[Any]:
    if mode == "sse":
        return parse_sse(body)
    if mode == "ndjson":
        return parse_ndjson(body)
    raise ValueError(f"not a streaming mode: {mode}")


def chunk_text(chunk: Any, response_path: str | None) -> str | None:
    """Text carried by one chunk, or ``None`` if it carries none."""
    if isinstance(chunk, str):
        return chunk
    paths = ([response_path] if response_path else []) + list(DELTA_FALLBACK_PATHS)
    for path in paths:
        value = get_path(chunk, path)
        if isinstance(value, str):
            return value
    return None


def assemble_text(chunks: list[Any], response_path: str | None) -> str | None:
    """Concatenate per-chunk text; ``None`` if no chunk carried any."""
    parts = [t for c in chunks if (t := chunk_text(c, response_path)) is not None]
    return "".join(parts) if parts else None
