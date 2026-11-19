"""Markdown and JSON rendering of a ``GateResult``."""

from __future__ import annotations

import json

from cyberredteam.gate.differential import GateResult

_LABEL = {"pass": "PASS", "regression": "REGRESSION", "inconclusive": "INCONCLUSIVE"}


def to_markdown(
    result: GateResult, *, target: str, suite: str, baseline: str, candidate: str
) -> str:
    lines = [
        f"## Canary gate: {_LABEL[result.status.value]}",
        "",
        f"- target: `{target}`",
        f"- suite: `{suite}`",
        f"- baseline campaign: `{baseline}`",
        f"- candidate campaign: `{candidate}`",
        "",
        "| technique | status | detail |",
        "|---|---|---|",
    ]
    for d in result.diffs:
        lines.append(f"| {d.technique} | {d.status.value} | {d.detail} |")
    if result.warnings:
        lines += ["", "Warnings:"] + [f"- {w}" for w in result.warnings]
    return "\n".join(lines) + "\n"


def to_json(result: GateResult, **meta: str) -> str:
    payload = result.model_dump(mode="json")
    payload["exit_code"] = result.exit_code
    payload.update(meta)
    return json.dumps(payload, indent=2, sort_keys=True)
