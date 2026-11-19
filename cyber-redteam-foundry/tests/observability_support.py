"""Helpers for WP11 export-path tests: a recording trace server behind the REAL
``weave.init`` / ``WeaveClient``. Nothing here touches the network."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock


class RecordingServer:
    """Stands in for the Weave trace server and records every payload sent."""

    def __init__(self) -> None:
        self.sent: list[tuple[str, Any]] = []

    def call_start(self, req: Any) -> Any:
        self.sent.append(("call_start", req))
        return SimpleNamespace(id="i", trace_id="t")

    def call_end(self, req: Any) -> None:
        self.sent.append(("call_end", req))

    def feedback_create(self, req: Any) -> Any:
        self.sent.append(("feedback_create", req))
        return SimpleNamespace(id="f", created_at=None, wb_user_id=None, payload={})

    def obj_create(self, req: Any) -> Any:
        return SimpleNamespace(digest="abc", object_id="o", version_index=0)

    def server_info(self) -> Any:
        return SimpleNamespace(
            min_required_weave_python_version="0.0.0", trace_server_version="9999.0.0"
        )

    def __getattr__(self, name: str) -> Any:
        if name in ("call_processor", "get_feedback_processor", "_next_trace_server"):
            raise AttributeError(name)
        return MagicMock()

    # ── inspection ──────────────────────────────────────────────────────────

    def payload_text(self) -> str:
        return json.dumps([r for _, r in self.sent], default=str)

    def op_names(self) -> list[str]:
        names = []
        for kind, req in self.sent:
            if kind == "call_start":
                names.append(str(req["start"]["op_name"]))
        return names


def install_recording_weave(monkeypatch: Any, server: RecordingServer) -> None:
    """Route the real ``weave.init`` to ``server`` instead of the network."""
    from weave.trace import weave_init

    monkeypatch.setattr(weave_init, "init_weave_get_server", lambda *a, **k: server)
    monkeypatch.setattr(weave_init, "get_wandb_auth_context",
                        lambda *a, **k: SimpleNamespace(wal_seed=lambda: "seed"))
    monkeypatch.setattr(weave_init, "get_username", lambda: "tester")
    monkeypatch.setattr(weave_init, "_setup_conversation_tracing", lambda *a, **k: None)
    monkeypatch.setattr(weave_init.init_message, "check_min_weave_version", lambda *a, **k: True)
    monkeypatch.setattr(weave_init.init_message, "check_min_trace_server_version",
                        lambda *a, **k: True)
    monkeypatch.setattr(weave_init.init_message, "print_init_message", lambda *a, **k: None)
    monkeypatch.setattr(weave_init, "use_server_cache", lambda: False)


def teardown_weave() -> None:
    from weave.trace.context import weave_client_context as wcc

    from cyberredteam.observability.weave_tracing import reset_tracing

    client = wcc.get_weave_client()
    if client is not None:
        try:
            client.finish()
        except Exception:
            pass
    wcc.set_weave_client_global(None)
    reset_tracing()
