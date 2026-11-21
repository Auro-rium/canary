"""Stack runner: Postgres DB, migrations, API, worker, fake targets, webhook catcher.

Everything it starts is torn down on exit (including Ctrl-C/SIGTERM): each child runs
in its own process group and the whole group is killed. The Postgres container
``canary-pg-test`` is reused and NEVER stopped or restarted; only the database
``canary_live_a`` is created fresh (and dropped again at the end unless asked not to).
"""

from __future__ import annotations

import http.server
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

FOUNDRY = Path(__file__).resolve().parents[1]
OUT = Path(__file__).resolve().parent / "out"
PG_CONTAINER = "canary-pg-test"
PG_HOST_PORT = 55432
DB_NAME = "canary_live_a"
PG_USER = "canary"
PG_PASSWORD = "canary"  # the throwaway test container's credentials (not a secret)
PYTHON = sys.executable
ADMIN_EMAIL = "admin@livetest.local"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def db_url() -> str:
    return f"postgresql+psycopg://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{PG_HOST_PORT}/{DB_NAME}"


class StackError(RuntimeError):
    pass


# --------------------------------------------------------------------------- catcher


class WebhookCatcher:
    """A tiny HTTP server that records every POST (path, parsed JSON body, time)."""

    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        catcher = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("content-length") or 0)
                raw = self.rfile.read(length) if length else b""
                try:
                    body: Any = json.loads(raw or b"null")
                except ValueError:
                    body = {"_unparsed": raw[:200].decode("utf-8", "replace")}
                with catcher._lock:
                    catcher.records.append({"t": time.time(), "path": self.path, "body": body})
                self.send_response(200)
                self.send_header("content-length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args: Any) -> None:
                return

        self.port = free_port()
        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def posts(self, prefix: str = "/") -> list[dict[str, Any]]:
        with self._lock:
            return [r for r in self.records if r["path"].startswith(prefix)]


# --------------------------------------------------------------------------- processes


@dataclass
class Proc:
    name: str
    popen: subprocess.Popen
    log_path: Path

    def alive(self) -> bool:
        return self.popen.poll() is None

    def kill_group(self, sig: int = signal.SIGTERM, wait_s: float = 10.0) -> None:
        if self.popen.poll() is not None:
            return
        try:
            os.killpg(self.popen.pid, sig)
        except ProcessLookupError:
            return
        try:
            self.popen.wait(timeout=wait_s)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(self.popen.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.popen.wait(timeout=5)


@dataclass
class FakeTargetProc:
    proc: Proc
    port: int
    key: str

    @property
    def endpoint(self) -> str:
        return f"http://127.0.0.1:{self.port}/chat"

    def admin(self, path: str, json_body: dict | None = None) -> dict:
        url = f"http://127.0.0.1:{self.port}/__admin/{path}"
        r = httpx.post(url, json=json_body, timeout=10) if json_body is not None else httpx.get(url, timeout=10)
        r.raise_for_status()
        return r.json()

    def configure(self, profile: str, **kw: Any) -> None:
        self.admin("config", {"profile": profile, **kw})

    def push_token(self, token: str) -> None:
        self.admin("token", {"token": token})

    def records(self) -> dict:
        return self.admin("records")


@dataclass
class Stack:
    env_base: dict[str, str]
    dry_run: bool
    out_dir: Path
    keep_db: bool = False
    catcher: WebhookCatcher | None = None
    api_port: int = 0
    procs: list[Proc] = field(default_factory=list)
    fake_targets: dict[str, FakeTargetProc] = field(default_factory=dict)
    worker: Proc | None = None
    api: Proc | None = None
    _db_created: bool = False
    _torn_down: bool = False

    # ---- env -------------------------------------------------------------------

    def _env(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        env = dict(self.env_base)
        env.update(extra or {})
        return env

    @property
    def logs(self) -> Path:
        return self.out_dir / "logs"

    @property
    def cwd(self) -> Path:
        d = self.out_dir / "cwd"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def spawn(self, name: str, argv: list[str], extra_env: dict[str, str] | None = None) -> Proc:
        self.logs.mkdir(parents=True, exist_ok=True)
        log_path = self.logs / f"{name}.out.log"
        fh = open(log_path, "ab", buffering=0)  # noqa: SIM115 - owned by the child
        p = subprocess.Popen(
            argv, cwd=self.cwd, env=self._env(extra_env), stdout=fh, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL, start_new_session=True,
        )
        fh.close()
        proc = Proc(name, p, log_path)
        self.procs.append(proc)
        return proc

    def run_cli(self, argv: list[str], extra_env: dict[str, str] | None = None, timeout: float = 120) -> subprocess.CompletedProcess:
        env = self._env({"NO_COLOR": "1", "COLUMNS": "400", "TERM": "dumb", **(extra_env or {})})
        return subprocess.run(argv, cwd=self.cwd, env=env, capture_output=True, text=True, timeout=timeout)

    # ---- database --------------------------------------------------------------

    def _psql(self, sql: str) -> None:
        r = subprocess.run(
            ["docker", "exec", PG_CONTAINER, "psql", "-U", PG_USER, "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-c", sql],
            capture_output=True, text=True, timeout=60,
        )
        if r.returncode != 0:
            raise StackError(f"psql failed: {r.stderr.strip()[:300]}")

    def check_postgres(self) -> None:
        r = subprocess.run(
            ["docker", "ps", "--filter", f"name=^{PG_CONTAINER}$", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=30,
        )
        if PG_CONTAINER not in r.stdout:
            raise StackError(f"docker container {PG_CONTAINER} is not running (this harness never starts or stops it)")

    def create_db(self) -> None:
        self.check_postgres()
        self._psql(f"DROP DATABASE IF EXISTS {DB_NAME} WITH (FORCE)")
        self._psql(f"CREATE DATABASE {DB_NAME}")
        self._db_created = True

    def migrate(self) -> None:
        r = self.run_cli([PYTHON, "-m", "cyberredteam.jobs.migrate"], timeout=300)
        if r.returncode != 0:
            raise StackError(f"migration failed: {(r.stderr or r.stdout)[-400:]}")

    # ---- processes -------------------------------------------------------------

    def start_catcher(self) -> None:
        self.catcher = WebhookCatcher()
        self.catcher.start()

    def start_api(self) -> None:
        self.api_port = free_port()
        self.api = self.spawn(
            "api",
            [PYTHON, "-m", "uvicorn", "cyberredteam.api:app", "--host", "127.0.0.1",
             "--port", str(self.api_port), "--log-level", "info"],
            {"LOG_FILE": str(self.logs / "api.app.log")},
        )
        self._wait_http(f"{self.api_base}/api/v2/auth/providers", self.api, 90)

    @property
    def api_base(self) -> str:
        return f"http://127.0.0.1:{self.api_port}"

    def start_worker(self) -> None:
        argv = [PYTHON, "-m", "livetest.dry_worker"] if self.dry_run else [PYTHON, "-m", "cyberredteam.jobs.worker"]
        self.worker = self.spawn("worker", argv, {"LOG_FILE": str(self.logs / "worker.app.log")})
        time.sleep(2.0)
        if not self.worker.alive():
            raise StackError(f"worker exited at startup; see {self.worker.log_path.name}")

    def kill_worker(self) -> None:
        """SIGKILL the worker's whole process group (simulates a crash)."""
        assert self.worker is not None
        self.worker.kill_group(signal.SIGKILL, wait_s=10)

    def start_fake_target(self, name: str, profile: str, key: str) -> FakeTargetProc:
        port = free_port()
        proc = self.spawn(
            f"fake-{name}",
            [PYTHON, "-m", "livetest.fake_target_server", "--port", str(port), "--profile", profile],
            {"FAKE_TARGET_KEY": key},
        )
        ft = FakeTargetProc(proc, port, key)
        self._wait_http(f"http://127.0.0.1:{port}/__admin/health", proc, 30)
        self.fake_targets[name] = ft
        return ft

    def _wait_http(self, url: str, proc: Proc, timeout_s: float) -> None:
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            if not proc.alive():
                raise StackError(f"{proc.name} exited during startup; see {proc.log_path.name}")
            try:
                if httpx.get(url, timeout=2).status_code < 500:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.4)
        raise StackError(f"{proc.name} did not become ready within {timeout_s:.0f}s")

    # ---- teardown --------------------------------------------------------------

    def teardown(self) -> list[str]:
        """Stop everything this stack started; return a list of leftover problems (empty = clean)."""
        problems: list[str] = []
        if self._torn_down:
            return problems
        self._torn_down = True
        for p in reversed(self.procs):
            try:
                p.kill_group(signal.SIGTERM, wait_s=8)
            except Exception as exc:  # noqa: BLE001
                problems.append(f"{p.name}: {type(exc).__name__}")
        if self.catcher is not None:
            try:
                self.catcher.stop()
            except Exception as exc:  # noqa: BLE001
                problems.append(f"catcher: {type(exc).__name__}")
        for p in self.procs:
            if p.alive():
                problems.append(f"{p.name} still alive")
        if self._db_created and not self.keep_db:
            try:
                self._psql(f"DROP DATABASE IF EXISTS {DB_NAME} WITH (FORCE)")
            except Exception as exc:  # noqa: BLE001
                problems.append(f"drop db: {type(exc).__name__}")
        return problems


def install_signal_handlers() -> None:
    """Turn SIGTERM into SystemExit so ``finally`` blocks (teardown) run; SIGINT already raises."""

    def _term(signum: int, frame: Any) -> None:
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGTERM, _term)
    signal.signal(signal.SIGHUP, _term)
