"""The repo's benign ``FakeTarget`` served over real HTTP on localhost.

``python -m livetest.fake_target_server --port P --profile always_safe``

Wraps ``tests/fixtures/fake_target.py`` (loaded by path) and adds:

* ``GET /.well-known/canary-verify.txt``: serves the ownership token the harness
  pushes after registration (so the real ownership flow can verify the target);
* timing records for every ``/chat`` request (start, end, status, campaign header)
  so the harness can assert rate, concurrency and header rules;
* ``/__admin/*`` (config, token, records, health). Admin traffic is never recorded.

The shared API key is read from the FAKE_TARGET_KEY environment variable and
enforced via ``X-Api-Key``; it is never written to the records.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib.util
import os
import sys
import time
from pathlib import Path
from typing import Any

FIXTURE = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "fake_target.py"
KEY_HEADER = "X-Api-Key"
CANARY = "CANARY-LIVE-A-7Q3X9"


def load_fixture() -> Any:
    spec = importlib.util.spec_from_file_location("livetest_fake_target_fixture", FIXTURE)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # dataclasses resolves annotations through sys.modules
    spec.loader.exec_module(mod)
    return mod


class State:
    def __init__(self, fixture: Any, key: str | None) -> None:
        self.fixture = fixture
        self.key = key
        self.token: str | None = None
        self.records: list[dict[str, Any]] = []
        self.in_flight = 0
        self.max_in_flight = 0
        self.fake: Any = None
        self.configure({"profile": "always_safe"})

    def configure(self, cfg: dict[str, Any]) -> None:
        allowed = {"profile", "n_turns", "delay_s", "fail_first", "fail_every", "k"}
        kwargs = {k: v for k, v in cfg.items() if k in allowed}
        kwargs["canary"] = CANARY
        if self.key:
            kwargs["required_headers"] = {KEY_HEADER: self.key}
        self.fake = self.fixture.FakeTarget(**kwargs)
        self.records = []
        self.in_flight = 0
        self.max_in_flight = 0


def build_app(state: State) -> Any:
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import JSONResponse, PlainTextResponse
    from starlette.routing import Route

    async def well_known(request: Request):
        if not state.token:
            return PlainTextResponse("not found", status_code=404)
        return PlainTextResponse(state.token + "\n")

    async def chat(request: Request):
        fake = state.fake
        t0 = time.time()
        state.in_flight += 1
        state.max_in_flight = max(state.max_in_flight, state.in_flight)
        try:
            raw = await request.body()
            if fake.profile == "slow":
                await asyncio.sleep(fake.delay_s)
            resp = fake.handle(request.method, request.url.path, dict(request.headers), raw)
        finally:
            state.in_flight -= 1
        state.records.append(
            {
                "t_start": t0,
                "t_end": time.time(),
                "status": resp.status,
                "campaign": request.headers.get("x-canary-campaign"),
                "turn": resp.body.get("turn") if isinstance(resp.body, dict) else None,
            }
        )
        out = JSONResponse(resp.body, status_code=resp.status)
        for name, value in resp.headers:
            out.headers.append(name, value)
        return out

    async def admin_config(request: Request):
        state.configure(await request.json())
        return JSONResponse({"ok": True, "profile": state.fake.profile})

    async def admin_token(request: Request):
        state.token = (await request.json()).get("token")
        return JSONResponse({"ok": True})

    async def admin_records(request: Request):
        return JSONResponse(
            {
                "count": len(state.records),
                "max_in_flight": state.max_in_flight,
                "profile": state.fake.profile,
                "records": state.records,
            }
        )

    async def admin_health(request: Request):
        return JSONResponse({"ok": True})

    return Starlette(
        routes=[
            Route("/.well-known/canary-verify.txt", well_known, methods=["GET"]),
            Route(state.fake.path, chat, methods=["GET", "POST", "PUT"]),
            Route("/__admin/config", admin_config, methods=["POST"]),
            Route("/__admin/token", admin_token, methods=["POST"]),
            Route("/__admin/records", admin_records, methods=["GET"]),
            Route("/__admin/health", admin_health, methods=["GET"]),
        ]
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--profile", default="always_safe")
    args = ap.parse_args()
    import uvicorn

    state = State(load_fixture(), os.environ.get("FAKE_TARGET_KEY") or None)
    state.configure({"profile": args.profile})
    uvicorn.run(build_app(state), host="127.0.0.1", port=args.port, log_level="warning", access_log=False)


if __name__ == "__main__":
    main()
