"""The /api/v2 OpenAPI schema is committed (``openapi/v2.json``) so the frontend
can generate its types from it. Any route or model change must update the
snapshot deliberately:

    UPDATE_OPENAPI_SNAPSHOT=1 uv run pytest tests/test_api_v2_openapi.py
    # or: uv run cyber-rt export-openapi --out openapi/v2.json
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from cyberredteam.api import v2_openapi

SNAPSHOT = Path(__file__).resolve().parents[1] / "openapi" / "v2.json"


def _current() -> dict:
    return json.loads(json.dumps(v2_openapi(), sort_keys=True))


def test_openapi_v2_snapshot():
    current = _current()
    if os.environ.get("UPDATE_OPENAPI_SNAPSHOT") == "1":
        SNAPSHOT.parent.mkdir(parents=True, exist_ok=True)
        SNAPSHOT.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n")
    assert SNAPSHOT.exists(), "run with UPDATE_OPENAPI_SNAPSHOT=1 to create the snapshot"
    assert json.loads(SNAPSHOT.read_text()) == current, (
        "the /api/v2 schema changed; regenerate openapi/v2.json (see module docstring)"
    )


def test_openapi_has_only_v2_paths_and_no_secret_fields():
    spec = _current()
    assert spec["paths"] and all(p.startswith("/api/v2") for p in spec["paths"])
    target_view = spec["components"]["schemas"]["TargetView"]["properties"]
    assert "oncall_webhook_url" not in target_view and "verification_token" not in target_view
    assert "oncall_webhook_configured" in target_view
