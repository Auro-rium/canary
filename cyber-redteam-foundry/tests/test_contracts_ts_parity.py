"""The TypeScript ConversationStatus union must list every Python status."""

import re
from pathlib import Path

from cyberredteam.contracts import ConversationStatus

TS = Path(__file__).resolve().parents[2] / "canary" / "src" / "lib" / "contracts.ts"


def test_every_conversation_status_in_contracts_ts():
    text = TS.read_text()
    m = re.search(r"export type ConversationStatus\s*=(.*?)\n\n", text, re.S)
    assert m, "ConversationStatus not found in contracts.ts"
    ts_values = set(re.findall(r"'([a-z_]+)'", m.group(1)))
    py_values = set(ConversationStatus.__args__)
    assert py_values <= ts_values, f"missing in contracts.ts: {py_values - ts_values}"
