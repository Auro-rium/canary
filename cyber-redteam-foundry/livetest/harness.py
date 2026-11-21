"""Shared context and helpers for the Live test A steps."""

from __future__ import annotations

import json
import re
import secrets as pysecrets
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import httpx

from livetest.capabilities import Capabilities
from livetest.report import Check, StepResult
from livetest.secrets_loader import Secrets
from livetest.spend import DOCTOR_PING_USD, SpendGuard
from livetest.stack import ADMIN_EMAIL, FOUNDRY, PYTHON, FakeTargetProc, Stack, StackError, db_url

CANARY = "CANARY-LIVE-A-7Q3X9"
FORBIDDEN_TOOL = "delete_record"
OPERATOR_EMAIL = "operator@livetest.local"
PACK_TECHNIQUE = "smoke_greeting"
PACK_TURNS = 3
EST_TURNS = 8  # worst-case turns per conversation for judge-cost estimates (matches the gate launcher's max_turns)
CLI = str(Path(PYTHON).parent / "cyber-rt")
TERMINAL = {"completed", "failed", "cancelled"}


def build_env(
    *, dry_run: bool, secrets: Secrets, enc_key: str, out_dir: Path, catcher_port: int,
    judge: tuple[str, str] | None,
) -> dict[str, str]:
    """A subprocess environment built from scratch (nothing inherited but PATH/HOME)."""
    import os

    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", ""),
        "LANG": "C.UTF-8",
        "PYTHONPATH": str(FOUNDRY),
        "PYTHONUNBUFFERED": "1",
        "CANARY_ENV": "dev",
        "CANARY_ALLOW_LOOPBACK_TARGETS": "1",
        "DATABASE_URL": db_url(),
        "CANARY_ENCRYPTION_KEY": enc_key,
        "CANARY_OPS_WEBHOOK_URL": f"http://127.0.0.1:{catcher_port}/ops",
        "CANARY_PLATFORM_ADMINS": ADMIN_EMAIL,
        "PLANNER_FACTORY": "cyberredteam.planners.worker:scripted",
        "PLANNER_PACKS_DIR": str(out_dir / "packs"),
        "TARGET_SAFETY_DIR": str(out_dir / "safety"),
        "WANDB_PROJECT": "canary-live",
        "WANDB_EXPORT_RAW_EVIDENCE": "false",
        "WANDB_MODE": "disabled" if dry_run else "online",
        "WANDB_DIR": str(out_dir / "wandb"),
        "WANDB_SILENT": "true",
        "WORKER_HEARTBEAT_INTERVAL_S": "2",
        "WORKER_STALE_AFTER_S": "8",
        "CANARY_JUDGE_VOTES": "3",
        "SESSION_COOKIE_SECURE": "false",
        "LOG_LEVEL": "INFO",
    }
    if dry_run:
        # No external calls: an unroutable Backboard URL and a random fake key (which also
        # gives the leak sweep a Backboard-key stand-in to look for).
        env["BACKBOARD_API_KEY"] = secrets.get("DRYRUN_BACKBOARD_API_KEY") or ""
        env["BACKBOARD_BASE_URL"] = "http://127.0.0.1:9/api"
    else:
        for name in ("BACKBOARD_API_KEY", "WANDB_API_KEY", "WANDB_ENTITY", "BACKBOARD_BASE_URL"):
            v = secrets.get(name)
            if v:
                env[name] = v
    if judge:
        prov, model = judge
        for role in ("JUDGE", "EVALUATOR"):
            env[f"BACKBOARD_{role}_PROVIDER"] = prov
            env[f"BACKBOARD_{role}_MODEL_NAME"] = model
        env["BACKBOARD_LLM_PROVIDER"] = prov
        env["BACKBOARD_MODEL_NAME"] = model
    return env


def prepare_dirs(out_dir: Path) -> None:
    """Fresh packs and safety dirs under out/ (the only files the harness feeds the worker)."""
    for sub in ("logs", "wandb", "cwd"):
        (out_dir / sub).mkdir(parents=True, exist_ok=True)
    packs = out_dir / "packs" / "livea"
    packs.mkdir(parents=True, exist_ok=True)
    shutil.copy(FOUNDRY / "packs" / "smoke" / "greeting.yaml", packs / "greeting.yaml")
    safety = out_dir / "safety"
    safety.mkdir(parents=True, exist_ok=True)
    (safety / "default.yaml").write_text(
        f'canary_values: ["{CANARY}"]\nforbidden_tools: ["{FORBIDDEN_TOOL}"]\n', encoding="utf-8"
    )


def _last_line(text: str) -> str:
    lines = [ln.strip() for ln in text.strip().splitlines() if ln.strip()]
    if not lines:
        raise StackError("expected CLI output, got nothing")
    return lines[-1]


def bootstrap_auth(stack: Stack, secrets: Secrets) -> dict[str, str]:
    """Org, operator and admin users and API keys, all through the `cyber-rt auth` CLI."""
    def cli(*args: str) -> str:
        r = stack.run_cli([CLI, "auth", *args], extra_env={"LOG_FILE": str(stack.logs / "cli.app.log")})
        if r.returncode != 0:
            raise StackError(f"cyber-rt auth {args[0]} failed: {secrets.scrub((r.stderr or r.stdout))[-300:]}")
        return _last_line(r.stdout)

    org = cli("create-org", "livetest-org")
    op_id = cli("add-user", "--org", org, "--role", "operator", "--email", OPERATOR_EMAIL, "--display-name", "livetest-operator")
    admin_id = cli("add-user", "--org", org, "--role", "admin", "--email", ADMIN_EMAIL, "--display-name", "livetest-admin")
    op_key = cli("create-api-key", op_id, "--name", "livetest-operator")
    admin_key = cli("create-api-key", admin_id, "--name", "livetest-admin")
    secrets.add_runtime("API_KEY_operator", op_key)
    secrets.add_runtime("API_KEY_admin", admin_key)
    return {"org": org, "operator_key": op_key, "admin_key": admin_key}


class Api:
    def __init__(self, base: str, key: str, sink: list[str]) -> None:
        self.client = httpx.Client(base_url=base, headers={"Authorization": f"Bearer {key}"}, timeout=30)
        self._sink = sink  # response texts kept in memory for the leak sweep

    def request(self, method: str, path: str, **kw: Any) -> httpx.Response:
        r = self.client.request(method, path, **kw)
        if len(self._sink) < 5000:
            self._sink.append(r.text)
        return r

    def get(self, path: str, **kw: Any) -> httpx.Response:
        return self.request("GET", path, **kw)

    def post(self, path: str, **kw: Any) -> httpx.Response:
        return self.request("POST", path, **kw)


@dataclass
class Target:
    name: str
    target_id: str
    fake: FakeTargetProc
    environment: str
    key: str
    token: str = ""


@dataclass
class Ctx:
    dry_run: bool
    stack: Stack
    secrets: Secrets
    spend: SpendGuard
    caps: Capabilities
    op: Api
    admin: Api
    out_dir: Path
    api_texts: list[str]
    result: StepResult | None = None
    targets: dict[str, Target] = field(default_factory=dict)
    campaigns: dict[str, str] = field(default_factory=dict)  # label -> campaign_id
    state: dict[str, Any] = field(default_factory=dict)
    _log_tokens_seen: float = 0.0

    # ---- assertions ------------------------------------------------------------

    def _detail(self, detail: str) -> str:
        return self.secrets.scrub(str(detail))[:400]

    def check(self, name: str, ok: bool, detail: str = "") -> bool:
        assert self.result is not None
        self.result.checks.append(Check(name, "pass" if ok else "fail", self._detail(detail)))
        return bool(ok)

    def skip(self, name: str, reason: str) -> None:
        assert self.result is not None
        self.result.checks.append(Check(name, "skip", "SKIP: " + reason))

    def note(self, text: str) -> None:
        assert self.result is not None
        self.result.notes.append(self._detail(text))

    # ---- targets ---------------------------------------------------------------

    def onboard(self, name: str, profile: str, environment: str = "staging", timeout_s: int = 60,
                oncall: bool = True, fake_cfg: dict[str, Any] | None = None) -> Target:
        """Register a fake target through API v2 and verify it through the real ownership flow."""
        key = pysecrets.token_urlsafe(24)
        self.secrets.add_runtime(f"TARGET_KEY_{name}", key)
        fake = self.stack.start_fake_target(name, profile, key)
        if fake_cfg:
            fake.configure(profile, **fake_cfg)
        payload: dict[str, Any] = {
            "name": f"livetest-{name}",
            "endpoint": fake.endpoint,
            "auth": {"type": "header", "header_name": "X-Api-Key", "value": key},
            "request_template": '{"message": "{{MESSAGE}}", "messages": "{{HISTORY}}"}',
            "response_path": "reply",
            "session_mode": "stateless_history",
            "tool_trace_path": "tool_calls",
            "environment": environment,
            "timeout_s": timeout_s,
        }
        if oncall:
            payload["oncall_webhook_url"] = self.stack.catcher.url(f"/oncall/{name}")  # type: ignore[union-attr]
        r = self.op.post("/api/v2/targets", json=payload)
        if r.status_code != 201:
            raise StackError(f"target registration failed: HTTP {r.status_code} {r.text[:200]}")
        body = r.json()
        tgt = Target(name, body["target"]["target_id"], fake, environment, key, body["verification_token"])
        self.secrets.add_runtime(f"VERIFY_TOKEN_{name}", tgt.token)
        fake.push_token(tgt.token)
        v = self.op.post(f"/api/v2/targets/{tgt.target_id}/verify", json={"method": "http_wellknown"})
        if v.status_code != 200 or not v.json().get("verified"):
            raise StackError(f"ownership verification failed: HTTP {v.status_code} {v.text[:200]}")
        self.targets[name] = tgt
        return tgt

    # ---- campaigns -------------------------------------------------------------

    def judge_estimate(self, conversations: int) -> float:
        return self.spend.conversations_usd(conversations, EST_TURNS)

    def launch(self, step: str, tgt: Target, *, trials: int, techniques: list[str] | None = None,
               max_turns: int = 4, parallel: int | None = None, rps: float | None = None,
               total: int | None = None, label: str | None = None, **extra: Any) -> str:
        techniques = techniques or [PACK_TECHNIQUE]
        convs = trials * len(techniques)
        est = self.judge_estimate(convs)
        self.spend.reserve_check(step, est)  # raises BudgetAbort before anything is sent
        prod = tgt.environment == "production"
        policy = {
            "techniques": techniques,
            "trials_per_technique": trials,
            "max_turns": max_turns,
            "max_parallel_conversations": parallel if parallel is not None else (2 if prod else 2),
            "rate_limit_rps": rps if rps is not None else (1.0 if prod else 20.0),
            "max_total_requests": total if total is not None else (300 if prod else 200),
            "max_llm_cost_usd": self.spend.campaign_cap_usd(est),
            **extra,
        }
        r = self.op.post("/api/v2/campaigns", json={"target_id": tgt.target_id, "policy": policy})
        if r.status_code != 201:
            raise StackError(f"campaign launch refused: HTTP {r.status_code} {r.text[:300]}")
        cid = r.json()["campaign_id"]
        self.campaigns[label or f"{step}:{cid[:8]}"] = cid
        self.spend.hold(step, est)
        self.state.setdefault("step_cids", {}).setdefault(step, []).append(cid)
        return cid

    def detail(self, cid: str) -> dict[str, Any]:
        r = self.op.get(f"/api/v2/campaigns/{cid}")
        r.raise_for_status()
        return r.json()

    def wait_for(self, cid: str, pred: Callable[[dict[str, Any]], bool], timeout: float, poll: float = 0.5) -> dict[str, Any]:
        deadline = time.time() + timeout
        d: dict[str, Any] = {}
        while time.time() < deadline:
            d = self.detail(cid)
            if pred(d):
                return d
            time.sleep(poll)
        return d

    def wait_terminal(self, cid: str, timeout: float = 180) -> dict[str, Any]:
        return self.wait_for(cid, lambda d: d["status"] in TERMINAL, timeout)

    def wait_requests(self, tgt: Target, n: int, timeout: float = 60) -> int:
        deadline = time.time() + timeout
        count = 0
        while time.time() < deadline:
            count = tgt.fake.records()["count"]
            if count >= n:
                return count
            time.sleep(0.2)
        return count

    # ---- spend settlement -------------------------------------------------------

    def settle_judge(self, step: str, cids: list[str]) -> float:
        """Charge the (conservative) judge estimate for conversations that ended, once judging is wired.

        Backboard reports tokens not prices and the judge is not charged to the campaign ledger,
        so the estimate (conversations x votes x repair x tokens x rate) is what counts against the cap.
        When the worker log shows token usage, the larger of estimate and observed is charged.
        """
        self.spend.release(step)
        convs = 0
        for cid in cids:
            d = self.detail(cid)
            convs += sum(1 for c in d["conversations"] if c["status"] != "running")
            ledger = float(d["budget"]["llm_cost_usd"])
            if ledger:
                self.spend.charge(step, ledger, "planner_ledger")
        est = self.judge_estimate(convs)
        observed = self.observed_usd_since_last()
        if self.caps.evaluation:
            self.spend.charge(step, max(est, observed), "judge_estimate" if est >= observed else "judge_observed_tokens")
        else:
            self.spend.charge(step, est, "would_judge_if_wired")
            self.note(f"judge not invoked on this build (no evaluation wiring): $0 charged; ${est:.4f} is the estimate once wired")
        return self.spend.step_total(step)

    def observed_usd_since_last(self) -> float:
        """Token usage logged by ObservableLLM in the worker app log, priced at the configured rates."""
        path = self.stack.logs / "worker.app.log"
        try:
            text = path.read_text(errors="replace")
        except OSError:
            return 0.0
        pin = pout = 0
        for m in re.finditer(r"\[LLM\] tokens: prompt=(\d+) completion=(\d+)", text):
            pin += int(m.group(1))
            pout += int(m.group(2))
        usd = pin / 1000 * self.spend.rates.usd_per_1k_in + pout / 1000 * self.spend.rates.usd_per_1k_out
        delta = max(0.0, usd - self._log_tokens_seen)
        self._log_tokens_seen = usd
        return delta


def sse_event_types(ctx: Ctx, cid: str, timeout: float = 30) -> list[str]:
    """Replay a finished campaign's persisted SSE events and return their types, in order."""
    types: list[str] = []
    deadline = time.time() + timeout
    with ctx.op.client.stream("GET", f"/api/v2/campaigns/{cid}/events", timeout=timeout) as r:
        for line in r.iter_lines():
            if line.startswith("data:"):
                try:
                    types.append(json.loads(line.split(":", 1)[1])["type"])
                except (ValueError, KeyError, TypeError):
                    pass
            if time.time() > deadline:
                break
    return types


def doctor_ping_charge(ctx_spend: SpendGuard, step: str) -> None:
    ctx_spend.reserve_check(step, DOCTOR_PING_USD)
    ctx_spend.charge(step, DOCTOR_PING_USD, "doctor_ping_estimate")

