"""Live test A steps 1-8 with machine-checked assertions."""

from __future__ import annotations

import json
import secrets as pysecrets
import subprocess
import time
from pathlib import Path
from typing import Callable

from livetest.harness import CANARY, CLI, PACK_TECHNIQUE, PACK_TURNS, Ctx, Target, sse_event_types

WIRING_EVAL = "needs the lead wiring (WP5 evaluation in the worker), not merged on this build"
WIRING_OBS = "needs the lead wiring (init_observability at worker start), not merged on this build"
WIRING_LAUNCHER = "needs the lead wiring (real CampaignLauncher behind `cyber-rt gate`), not merged on this build"


def _ok_conv(c: dict, turns: int = PACK_TURNS) -> bool:
    return c["status"] == "completed" and c["turns"] == turns


def _after(records: list[dict], t: float) -> list[dict]:
    return [r for r in records if r["t_start"] > t]


# ------------------------------------------------------------------------- step 1


def step1_onboard(ctx: Ctx) -> None:
    me = ctx.op.get("/api/v2/me")
    ctx.check("operator API key signs in as operator", me.status_code == 200 and me.json().get("role") == "operator", f"HTTP {me.status_code}")
    me_a = ctx.admin.get("/api/v2/me")
    ctx.check("admin API key signs in as admin", me_a.status_code == 200 and me_a.json().get("role") == "admin", f"HTTP {me_a.status_code}")

    # SSRF guard stays intact under the loopback allowance: metadata and RFC1918 are still refused.
    for url in ("http://169.254.169.254/chat", "http://10.0.0.5/chat"):
        r = ctx.op.post("/api/v2/targets", json={
            "name": "ssrf-probe", "endpoint": url, "auth": {"type": "none"}, "session_mode": "stateless_history",
            "request_template": '{"message": "{{MESSAGE}}", "messages": "{{HISTORY}}"}', "response_path": "reply",
            "environment": "staging"})
        ctx.check(f"registration of {url.split('/')[2]} still refused (SSRF guard)", r.status_code == 422, f"HTTP {r.status_code}")

    key = pysecrets.token_urlsafe(24)
    ctx.secrets.add_runtime("TARGET_KEY_main", key)
    fake = ctx.stack.start_fake_target("main", "always_safe", key)
    payload = {
        "name": "livetest-main", "endpoint": fake.endpoint,
        "auth": {"type": "header", "header_name": "X-Api-Key", "value": key},
        "request_template": '{"message": "{{MESSAGE}}", "messages": "{{HISTORY}}"}', "response_path": "reply",
        "session_mode": "stateless_history", "tool_trace_path": "tool_calls", "environment": "staging",
        "oncall_webhook_url": ctx.stack.catcher.url("/oncall/main"),  # type: ignore[union-attr]
    }
    r = ctx.op.post("/api/v2/targets", json=payload)
    created = r.json() if r.status_code == 201 else {}
    ctx.check("registration returns 201 for the loopback target", r.status_code == 201, f"HTTP {r.status_code} {r.text[:150] if r.status_code != 201 else ''}")
    if not created:
        return
    tgt_id = created["target"]["target_id"]
    token = created["verification_token"]
    ctx.secrets.add_runtime("VERIFY_TOKEN_main", token)
    ctx.check("target starts unverified", created["target"]["verified"] is False)
    ctx.check("response never echoes the target key", key not in r.text)
    ctx.check("on-call webhook stored but only reported as configured", created["target"]["oncall_webhook_configured"] is True and "oncall" not in json.dumps(created["target"]).replace("oncall_webhook_configured", ""))

    pre = ctx.op.post("/api/v2/campaigns", json={"target_id": tgt_id, "policy": {
        "techniques": [PACK_TECHNIQUE], "trials_per_technique": 1, "max_turns": 3, "max_parallel_conversations": 1,
        "rate_limit_rps": 1.0, "max_total_requests": 10, "max_llm_cost_usd": 0.01}})
    ctx.check("campaign on an unverified target is refused (403)", pre.status_code == 403, f"HTTP {pre.status_code}")

    v0 = ctx.op.post(f"/api/v2/targets/{tgt_id}/verify", json={"method": "http_wellknown"})
    ctx.check("verify before the token is published fails", v0.status_code == 200 and v0.json()["verified"] is False, v0.text[:120])

    fake.push_token(token)
    v1 = ctx.op.post(f"/api/v2/targets/{tgt_id}/verify", json={"method": "http_wellknown"})
    ctx.check("verify after publishing the token succeeds (real ownership flow)", v1.status_code == 200 and v1.json()["verified"] is True, v1.text[:160])
    got = ctx.op.get(f"/api/v2/targets/{tgt_id}").json()
    ctx.check("target now verified via http_wellknown", got["verified"] is True and got["verified_method"] == "http_wellknown")
    ctx.targets["main"] = Target("main", tgt_id, fake, "staging", key, token)


# ------------------------------------------------------------------------- step 2


def _wandb_run_count(ctx: Ctx, since: float) -> tuple[int | None, str]:
    """Runs created in the canary-live project since ``since`` (None if W&B's API is unusable)."""
    try:
        import wandb  # noqa: PLC0415

        api = wandb.Api(api_key=ctx.secrets.get("WANDB_API_KEY"), timeout=30)
        entity = ctx.secrets.get("WANDB_ENTITY")
        runs = list(api.runs(f"{entity}/canary-live", per_page=50))
        n = 0
        for run in runs:
            created = getattr(run, "created_at", "")
            try:
                from datetime import datetime  # noqa: PLC0415

                ts = datetime.fromisoformat(str(created).replace("Z", "+00:00")).timestamp()
            except ValueError:
                continue
            if ts >= since - 5:
                n += 1
        return n, f"https://wandb.ai/{entity}/canary-live"
    except Exception as exc:  # noqa: BLE001
        return None, f"W&B API check unavailable ({type(exc).__name__})"


def step2_smoke(ctx: Ctx) -> None:
    tgt = ctx.targets["main"]
    tgt.fake.configure("always_safe")
    t_start = time.time()
    cid = ctx.launch("s2", tgt, trials=5, label="baseline")
    d = ctx.wait_terminal(cid, 150)
    ctx.state["baseline"] = cid
    ctx.check("campaign completed", d["status"] == "completed", d["status"])
    convs = d["conversations"]
    ctx.check("5 conversations, all completed with 3 persisted turns each", len(convs) == 5 and all(_ok_conv(c) for c in convs), str([(c["status"], c["turns"]) for c in convs]))
    rec = tgt.fake.records()
    ctx.check("target received exactly the persisted turns (15 requests)", rec["count"] == 15, f"count={rec['count']}")
    if convs:
        detail = ctx.op.get(f"/api/v2/conversations/{convs[0]['conversation_id']}").json()
        turns = detail["conversation"]["turns"]
        ctx.check("transcript readable via API with responses stored", len(turns) == PACK_TURNS and all(t["response_text"] for t in turns))
        ctx.check("default read is redacted (raw=false)", detail["raw"] is False)
    types = sse_event_types(ctx, cid)
    ctx.check("persisted event stream replays and ends with campaign_complete", bool(types) and types[-1] == "campaign_complete", str(types[-3:]))
    if ctx.caps.evaluation:
        verdicts = [c["verdict"] for c in convs]
        ctx.check("every conversation has a stored verdict", all(v is not None for v in verdicts), str(verdicts))
        ctx.check("no confirmed finding on the always_safe profile", "confirmed" not in verdicts, str(verdicts))
        ctx.check("verdict events were emitted", "verdict" in types, str(sorted(set(types))))
    else:
        ctx.skip("verdicts stored / verdict events", WIRING_EVAL)
    ctx.state["smoke_started"] = t_start
    ctx.state["smoke_cid_detail"] = d["budget"]


def step2_wandb(ctx: Ctx) -> None:
    """W&B / Weave presence check; runs after the smoke campaign (called by step 2)."""
    if ctx.dry_run:
        ctx.skip("W&B run exists in canary-live", "dry-run: WANDB_MODE=disabled, no external calls")
        wb = ctx.out_dir / "wandb"
        files = [p for p in wb.rglob("*") if p.is_file()] if wb.exists() else []
        ctx.check("dry-run wrote no W&B run files", not files, f"{len(files)} files")
        return
    if not ctx.caps.observability:
        ctx.skip("W&B run / Weave traces appear", WIRING_OBS)
        return
    time.sleep(10)  # let the reporter flush
    n, where = _wandb_run_count(ctx, ctx.state.get("smoke_started", time.time()))
    if n is None:
        ctx.skip("W&B run created via API", where)
        ctx.note("W&B project to inspect manually: canary-live (entity from the secrets file)")
    else:
        ctx.check("a W&B run was created in canary-live during the smoke run", n >= 1, f"{n} run(s) since start")
        ctx.note(f"W&B project: {where}")
    wb = ctx.out_dir / "wandb"
    files = [p for p in wb.rglob("*") if p.is_file()] if wb.exists() else []
    ctx.check("local W&B run files exist for the sweep", len(files) > 0, f"{len(files)} files")


def step2(ctx: Ctx) -> None:
    step2_smoke(ctx)
    step2_wandb(ctx)


# ------------------------------------------------------------------------- step 3


def step3_critical(ctx: Ctx) -> None:
    tgt = ctx.targets["main"]
    tgt.fake.configure("leaks_after_n_turns", n_turns=2)
    cid = ctx.launch("s3", tgt, trials=5, label="regression")
    d = ctx.wait_terminal(cid, 150)
    ctx.state["regression"] = cid
    ctx.check("campaign finished", d["status"] == "completed", d["status"])
    convs = d["conversations"]
    if not ctx.caps.evaluation:
        ctx.skip("conversations stopped by the critical monitor (stopped_monitor)",
                 "canary values reach the engine only through TARGET_SAFETY_DIR, which " + WIRING_EVAL)
        ctx.skip("alert received at the on-call catcher", WIRING_EVAL)
        ctx.skip("confirmed finding exists", WIRING_EVAL)
        ctx.note(f"without the wiring the leak is not detected: statuses {sorted({c['status'] for c in convs})}")
        return
    ctx.check("every conversation stopped_monitor", len(convs) == 5 and all(c["status"] == "stopped_monitor" for c in convs), str([c["status"] for c in convs]))
    ctx.check("each stopped at the leaking turn (3 turns persisted)", all(c["turns"] == 3 for c in convs), str([c["turns"] for c in convs]))
    posts = [p for p in ctx.stack.catcher.posts("/oncall/main") if p["body"].get("campaign_id") == cid]  # type: ignore[union-attr]
    ctx.check("on-call alert received at the catcher", len(posts) >= 1, f"{len(posts)} alerts")
    if posts:
        body = json.dumps(posts[0]["body"])
        ctx.check("alert carries ids and hit names only, never the canary text", CANARY not in body, "")
        ctx.check("alert names a canary hit", "canary" in body.lower(), "")
    fs = ctx.op.get("/api/v2/findings", params={"campaign_id": cid}).json()
    items = fs.get("items", [])
    ctx.check("a finding was created for the campaign", len(items) >= 1, f"{len(items)}")
    verdicts = [c["verdict"] for c in convs]
    ctx.check("verdicts confirmed on every leaking conversation", all(v == "confirmed" for v in verdicts), str(verdicts))
    ctx.check("finding severity is critical", any(i["severity"] == "critical" for i in items), str([i["severity"] for i in items]))


# ------------------------------------------------------------------------- step 4


def step4_production(ctx: Ctx) -> None:
    prod = ctx.onboard("prod", "slow", environment="production", fake_cfg={"delay_s": 2.5})
    fake = prod.fake
    before = fake.records()["count"]
    total_before = ctx.op.get("/api/v2/campaigns").json()["total"]
    base = {"techniques": [PACK_TECHNIQUE], "trials_per_technique": 3, "max_turns": 4,
            "max_parallel_conversations": 2, "rate_limit_rps": 1.0, "max_total_requests": 300, "max_llm_cost_usd": 0.01}
    bad = {
        "rps 5 (> 1)": {"rate_limit_rps": 5.0},
        "parallel 4 (> 2)": {"max_parallel_conversations": 4},
        "total 500 (> 300)": {"max_total_requests": 500},
        "all defaults (4 parallel, 500 total)": {"max_parallel_conversations": 4, "max_total_requests": 500, "rate_limit_rps": 1.0},
        "staging-only technique": {"techniques": ["denial-of-service"]},
        "destructive tools": {"allow_destructive_tools": True},
    }
    for label, delta in bad.items():
        r = ctx.op.post("/api/v2/campaigns", json={"target_id": prod.target_id, "policy": {**base, **delta}})
        ctx.check(f"over-limit policy refused: {label}", r.status_code == 422, f"HTTP {r.status_code}")
    ctx.check("refused policies sent nothing to the target", fake.records()["count"] == before, f"{before} -> {fake.records()['count']}")
    ctx.check("refused policies created no campaign rows", ctx.op.get("/api/v2/campaigns").json()["total"] == total_before)

    cid = ctx.launch("s4", prod, trials=3, parallel=2, rps=1.0, total=300, label="production")
    d = ctx.wait_terminal(cid, 180)
    ctx.check("production campaign completed", d["status"] == "completed", d["status"])
    ctx.check("policy stored with production limits", d["policy"]["rate_limit_rps"] <= 1.0 and d["policy"]["max_parallel_conversations"] <= 2 and d["policy"]["max_total_requests"] <= 300)
    rec = fake.records()
    rs = sorted(rec["records"], key=lambda r: r["t_start"])
    ctx.check("target saw 9 requests (3 conversations x 3 turns)", len(rs) == 9, f"{len(rs)}")
    ctx.check("total requests <= 300", len(rs) <= 300)
    ctx.check("X-Canary-Campaign on every request and equal to the campaign id", len(rs) > 0 and all(r["campaign"] == cid for r in rs), str({r["campaign"] for r in rs})[:120])
    gaps = [b["t_start"] - a["t_start"] for a, b in zip(rs, rs[1:])]
    ctx.check("rps <= 1 (no two requests closer than 0.85s)", bool(gaps) and min(gaps) >= 0.85, f"min gap {min(gaps):.2f}s" if gaps else "no gaps")
    ev = sorted([(r["t_start"], 1) for r in rs] + [(r["t_end"], -1) for r in rs])
    cur = peak = 0
    for _, delta in sorted(ev, key=lambda e: (e[0], e[1])):
        cur += delta
        peak = max(peak, cur)
    ctx.check("at most 2 requests in flight (from recorded intervals)", peak <= 2, f"peak {peak}")
    ctx.check("server-side in-flight peak <= 2 and parallelism was exercised (== 2)", rec["max_in_flight"] == 2, f"peak {rec['max_in_flight']}")
    ctx.check("budget ledger counted the requests", d["budget"]["requests_used"] >= len(rs), f"{d['budget']['requests_used']}")


# ------------------------------------------------------------------------- step 5


def step5_cancel_kill(ctx: Ctx) -> None:
    ctl = ctx.onboard("ctl", "slow", fake_cfg={"delay_s": 1.0})
    fake = ctl.fake

    # cancel
    cid = ctx.launch("s5", ctl, trials=4, parallel=1, rps=5.0, label="cancel")
    ctx.wait_requests(ctl, 2, 60)
    t0 = time.time()
    r = ctx.op.post(f"/api/v2/campaigns/{cid}/cancel")
    t1 = time.time()
    ctx.check("cancel accepted", r.status_code == 200 and r.json()["status"] in {"cancelling", "cancelled"}, f"HTTP {r.status_code} {r.text[:80]}")
    d = ctx.wait_terminal(cid, 60)
    ctx.check("campaign ended cancelled", d["status"] == "cancelled", d["status"])
    late = _after(fake.records()["records"], t1)
    ctx.check("cancel stops within one turn (<= 1 request started after the cancel returned)", len(late) <= 1, f"{len(late)} late requests")
    ctx.check("no conversation left running", all(c["status"] != "running" for c in d["conversations"]), str([c["status"] for c in d["conversations"]]))
    ctx.check("cancel took effect promptly (< 15s)", time.time() - t0 < 15, f"{time.time() - t0:.1f}s")
    ctx.state["cancel_cid"] = cid

    # kill switch
    fake.configure("slow", delay_s=1.0)  # reset records
    forbidden = ctx.op.post("/api/v2/admin/kill-switch", json={"enabled": True, "reason": "livetest"})
    ctx.check("kill switch refuses a non-admin operator (403)", forbidden.status_code == 403, f"HTTP {forbidden.status_code}")
    cid2 = ctx.launch("s5", ctl, trials=4, parallel=1, rps=5.0, label="killswitch")
    try:
        ctx.wait_requests(ctl, 2, 60)
        k = ctx.admin.post("/api/v2/admin/kill-switch", json={"enabled": True, "reason": "livetest step 5"})
        t_kill = time.time()
        ctx.check("platform admin can flip the kill switch", k.status_code == 200 and k.json()["enabled"] is True, f"HTTP {k.status_code} {k.text[:100]}")
        d2 = ctx.wait_terminal(cid2, 60)
        late2 = _after(fake.records()["records"], t_kill)
        ctx.check("kill switch stops within one turn (<= 1 request after the flip)", len(late2) <= 1, f"{len(late2)} late requests")
        ctx.check("conversations ended stopped_killed", all(c["status"] in {"stopped_killed", "completed"} for c in d2["conversations"]) and any(c["status"] == "stopped_killed" for c in d2["conversations"]), str([c["status"] for c in d2["conversations"]]))
        refused = ctx.op.post("/api/v2/campaigns", json={"target_id": ctl.target_id, "policy": {
            "techniques": [PACK_TECHNIQUE], "trials_per_technique": 1, "max_turns": 3, "max_parallel_conversations": 1,
            "rate_limit_rps": 1.0, "max_total_requests": 10, "max_llm_cost_usd": 0.01}})
        n_before = fake.records()["count"]
        ctx.check("new launches are refused while the kill switch is on (409)", refused.status_code == 409, f"HTTP {refused.status_code}")
        ctx.check("refused launch sent nothing", fake.records()["count"] == n_before)
    finally:
        off = ctx.admin.post("/api/v2/admin/kill-switch", json={"enabled": False, "reason": "livetest done"})
        ctx.check("kill switch switched off again", off.status_code == 200 and off.json()["enabled"] is False, f"HTTP {off.status_code}")


# ------------------------------------------------------------------------- step 6


def step6_resilience(ctx: Ctx) -> None:
    # flaky_500
    flaky = ctx.onboard("flaky", "flaky_500", fake_cfg={"fail_first": 1, "fail_every": 4})
    cid = ctx.launch("s6", flaky, trials=2, parallel=1, rps=20.0, label="flaky")
    d = ctx.wait_terminal(cid, 150)
    rec = flaky.fake.records()["records"]
    n500 = sum(1 for r in rec if r["status"] == 500)
    n2xx = sum(1 for r in rec if 200 <= r["status"] < 300)
    ctx.check("flaky_500: campaign completed and every conversation completed", d["status"] == "completed" and all(_ok_conv(c) for c in d["conversations"]), str([(c["status"], c["turns"]) for c in d["conversations"]]))
    ctx.check("flaky_500: the target did return 500s", n500 >= 1, f"{n500} x 500")
    ctx.check("retries only on non-2xx: exactly one 2xx per persisted turn", n2xx == sum(c["turns"] for c in d["conversations"]), f"{n2xx} ok vs {sum(c['turns'] for c in d['conversations'])} turns")
    ctx.check("budget charged per HTTP request (500s included)", d["budget"]["requests_used"] == len(rec), f"ledger {d['budget']['requests_used']} vs {len(rec)} requests")

    # slow with a short client timeout
    slow = ctx.onboard("slow", "slow", timeout_s=1, fake_cfg={"delay_s": 2.0})
    cid = ctx.launch("s6", slow, trials=1, parallel=1, rps=20.0, label="slow-timeout")
    t0 = time.time()
    d = ctx.wait_terminal(cid, 150)
    srec = slow.fake.records()
    ctx.check("slow: campaign terminates (no hang) despite every request timing out", d["status"] in TERMINAL_OK, d["status"])
    ctx.check("slow: conversation ended in a target-error/error state, not completed", all(c["status"] in {"stopped_target_error_streak", "error"} for c in d["conversations"]), str([c["status"] for c in d["conversations"]]))
    ctx.check("slow: retries are bounded", srec["count"] <= 30, f"{srec['count']} requests in {time.time() - t0:.0f}s")

    # worker killed mid-run
    rz = ctx.onboard("resume", "slow", fake_cfg={"delay_s": 1.0})
    cid = ctx.launch("s6", rz, trials=4, parallel=1, rps=5.0, label="resume")
    n_before = ctx.wait_requests(rz, 4, 60)
    ctx.stack.kill_worker()
    t_kill = time.time()
    time.sleep(4)
    mid = ctx.detail(cid)
    ctx.check("worker killed mid-run: campaign not finished", mid["status"] not in TERMINAL_OK, mid["status"])
    ctx.stack.start_worker()
    d = ctx.wait_terminal(cid, 240)
    ctx.check("campaign resumed and completed after the worker restart", d["status"] == "completed", f"{d['status']} after {time.time() - t_kill:.0f}s")
    convs = d["conversations"]
    keys = {(c["technique"], c["trial_index"]) for c in convs}
    ctx.check("exactly 4 conversations (no duplicates after resume)", len(convs) == 4 and len(keys) == 4, f"{len(convs)} rows, {len(keys)} distinct")
    ctx.check("every conversation completed with its 3 turns (no duplicated turns)", all(_ok_conv(c) for c in convs), str([(c["status"], c["turns"]) for c in convs]))
    ctx.check("requests continued after the restart", rz.fake.records()["count"] > n_before, f"{n_before} -> {rz.fake.records()['count']}")


TERMINAL_OK = {"completed", "failed", "cancelled"}


# ------------------------------------------------------------------------- step 7


def _gate(ctx: Ctx, args: list[str], timeout: float = 600) -> subprocess.CompletedProcess:
    return ctx.stack.run_cli([CLI, "gate", *args], extra_env={"LOG_FILE": str(ctx.stack.logs / "gate.app.log")}, timeout=timeout)


def step7_gate(ctx: Ctx) -> None:
    # Synthetic gate sanity (free, always runs): proves the CLI's pass/regression exit codes.
    ok = _gate(ctx, ["--demo"])
    reg = _gate(ctx, ["--demo", "--demo-inject-regression"])
    ctx.check("gate CLI works on synthetic data: identical passes (exit 0)", ok.returncode == 0, f"exit {ok.returncode}")
    ctx.check("gate CLI works on synthetic data: injected regression fails (exit 1)", reg.returncode == 1, f"exit {reg.returncode}")
    ctx.note("the two checks above use the built-in synthetic demo data, not this run's campaigns")
    if not (ctx.caps.gate_launcher and ctx.caps.evaluation):
        why = WIRING_LAUNCHER if not ctx.caps.gate_launcher else WIRING_EVAL
        ctx.skip("gate vs a real baseline: identical run passes", why)
        ctx.skip("gate vs a real baseline: injected regression fails", why)
        return
    tgt = ctx.targets["main"]
    base = ctx.state.get("baseline")
    if not base:
        ctx.skip("gate vs a real baseline", "step 2 produced no baseline campaign")
        return
    known = set(ctx.campaigns.values())
    common = ["--target", tgt.target_id, "--suite", "livea", "--baseline", base, "--launch-timeout", "600"]
    # identical run (launcher campaigns: 5 trials of the greeting pack)
    ctx.spend.reserve_check("s7", ctx.judge_estimate(10))
    ctx.spend.hold("s7", ctx.judge_estimate(10))
    tgt.fake.configure("always_safe")
    same = _gate(ctx, common + ["--json-out", str(ctx.out_dir / "gate_identical.json")])
    ctx.check("identical run passes the gate (exit 0)", same.returncode == 0, f"exit {same.returncode}")
    tgt.fake.configure("leaks_after_n_turns", n_turns=2)
    regress = _gate(ctx, common + ["--json-out", str(ctx.out_dir / "gate_regression.json")])
    tgt.fake.configure("always_safe")
    ctx.check("injected regression fails the gate (exit 1)", regress.returncode == 1, f"exit {regress.returncode}")
    ctx.note("real launcher campaigns use the launcher's own policy (5 trials, max_llm_cost_usd 2.0 on the ledger, which only counts planner spend = $0); the harness charged the judge estimate for 10 conversations against the cap")
    ctx.state.setdefault("step_cids", {})["s7"] = [c for c in _launcher_campaigns(ctx, tgt.target_id) if c not in known]


def _launcher_campaigns(ctx: Ctx, target_id: str) -> list[str]:
    r = ctx.op.get("/api/v2/campaigns", params={"target_id": target_id, "page_size": 100}).json()
    return [i["campaign_id"] for i in r["items"]]


# ------------------------------------------------------------------------- step 8


def _scan_bytes(data: bytes, needles: dict[str, bytes], where: str, hits: dict[str, list[str]]) -> None:
    for name, nb in needles.items():
        if nb in data:
            hits.setdefault(name, []).append(where)


def step8_leak_sweep(ctx: Ctx) -> None:
    needles = {n: v.encode() for n, v in ctx.secrets.sweep_values().items()}
    ctx.check("sweep has secrets to look for (target keys, API keys, Backboard/W&B/encryption keys)", len(needles) >= 4, f"{len(needles)} values (names only: {sorted(needles)})")
    hits: dict[str, list[str]] = {}
    scanned = {"files": 0, "bytes": 0, "db_tables": 0, "db_rows": 0, "api_responses": 0, "catcher_posts": 0, "fake_records": 0}

    # positive control: the scanner must find a planted value
    probe_name, probe_val = "SWEEP_CONTROL", "livetest-sweep-control-value-1234"
    ctx.secrets.add_runtime(probe_name, probe_val)
    ctx_probe: dict[str, list[str]] = {}
    _scan_bytes(f"x {probe_val} y".encode(), {probe_name: probe_val.encode()}, "control", ctx_probe)
    ctx.check("positive control: the scanner detects a planted value", probe_name in ctx_probe)

    roots = [ctx.out_dir / "logs", ctx.out_dir / "wandb"]
    import tempfile  # noqa: PLC0415

    for extra in Path(tempfile.gettempdir()).glob("canary-wandb*"):
        roots.append(extra)
    for root in roots:
        for p in root.rglob("*") if root.exists() else []:
            if p.is_file():
                data = p.read_bytes()
                scanned["files"] += 1
                scanned["bytes"] += len(data)
                _scan_bytes(data, needles, f"file:{p.relative_to(root.parent) if root.parent in p.parents else p.name}", hits)

    # The ownership token is returned once to the registering client by design, so API responses
    # are not searched for it; it must still never appear anywhere else (logs, DB, events, ...).
    api_needles = {n: v for n, v in needles.items() if not n.startswith("VERIFY_TOKEN_")}
    for text in ctx.api_texts:
        scanned["api_responses"] += 1
        _scan_bytes(text.encode(), api_needles, "api-response", hits)
    for post in ctx.stack.catcher.posts("/"):  # type: ignore[union-attr]
        scanned["catcher_posts"] += 1
        _scan_bytes(json.dumps(post["body"]).encode(), needles, f"catcher:{post['path']}", hits)
    for name, tgt in ctx.targets.items():
        rec = tgt.fake.records()
        scanned["fake_records"] += rec["count"]
        _scan_bytes(json.dumps(rec).encode(), {n: v for n, v in needles.items() if n != f"TARGET_KEY_{name}"}, f"fake:{name}", hits)

    # every table and column in the database (events, audit rows, turns, verdicts, targets, ...)
    from sqlalchemy import create_engine, inspect, text  # noqa: PLC0415

    from livetest.stack import db_url  # noqa: PLC0415

    eng = create_engine(db_url())
    try:
        insp = inspect(eng)
        with eng.connect() as conn:
            for table in insp.get_table_names():
                scanned["db_tables"] += 1
                result = conn.execute(text(f'SELECT * FROM "{table}"'))  # noqa: S608 - table names from the inspector
                for row in result:
                    scanned["db_rows"] += 1
                    blob = json.dumps([str(v) for v in row], default=str).encode()
                    _scan_bytes(blob, needles, f"db:{table}", hits)
    finally:
        eng.dispose()

    summary = {n: sorted(set(w)) for n, w in hits.items()}
    ctx.check("ZERO hits for any secret value across logs, W&B files, events, audit rows, DB, API responses and webhook posts", not hits, f"hits: {summary}" if hits else f"scanned {scanned}")
    ctx.check("sweep actually scanned data (logs, DB rows, responses)", scanned["files"] > 0 and scanned["db_rows"] > 0 and scanned["api_responses"] > 0, str(scanned))
    ctx.note(f"scanned: {scanned}")
    ctx.note(f"secret names searched: {sorted(needles)}")


STEPS: list[tuple[int, str, Callable[[Ctx], None]]] = [
    (1, "Onboard target via API v2 + ownership verification", step1_onboard),
    (2, "Smoke run (always_safe)", step2),
    (3, "Critical stop (leaks_after_n_turns)", step3_critical),
    (4, "Production limits", step4_production),
    (5, "Cancel and kill switch", step5_cancel_kill),
    (6, "Resilience (flaky_500, slow, worker kill)", step6_resilience),
    (7, "Gate (cyber-rt gate)", step7_gate),
    (8, "Leak sweep", step8_leak_sweep),
]
