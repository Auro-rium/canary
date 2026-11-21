"""Live test A entry point: ``python -m livetest [--dry-run | --yes] [options]``."""

from __future__ import annotations

import argparse
import secrets as pysecrets
import socket
import subprocess
import sys
import time
import traceback
from pathlib import Path

from livetest import capabilities
from livetest.harness import Api, Ctx, bootstrap_auth, build_env, doctor_ping_charge, prepare_dirs
from livetest.report import RunReport, StepResult
from livetest.secrets_loader import MAIN_ENV_PATH, MissingSecrets, Secrets
from livetest.spend import (
    DEFAULT_BUDGET_USD,
    HARD_CAP_USD,
    BudgetAbort,
    Rates,
    SpendGuard,
)
from livetest.stack import FOUNDRY, OUT, Stack, StackError, install_signal_handlers
from livetest.steps import STEPS

# Cheap judge candidates, tried in order with `cyber-rt doctor` until one answers.
# Rates are conservative USD per 1k tokens (input, output); the code exposes no model list and no
# prices, so these are the harness's own configuration. Override with --judge-model/--rate-in/--rate-out.
# List prices times RATE_MARGIN, so a Backboard markup or a fallback to a pricier model stays
# inside the estimate. Explicit --rate-in/--rate-out are used exactly as given.
RATE_MARGIN = 1.5
CANDIDATES = [
    (prov, name, rin * RATE_MARGIN, rout * RATE_MARGIN)
    for prov, name, rin, rout in [
        ("openai", "gpt-4o-mini", 0.00015, 0.0006),
        ("google", "gemini-2.0-flash", 0.0001, 0.0004),
        ("anthropic", "claude-haiku-4-5", 0.001, 0.005),
        ("openai", "gpt-4.1-mini", 0.0004, 0.0016),
    ]
]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(prog="livetest", description="Canary Live test A: real backend vs the benign fake_target")
    ap.add_argument("--dry-run", action="store_true", help="fake LLM, WANDB_MODE=disabled, no external calls, $0")
    ap.add_argument("--yes", action="store_true", help="required for a real run: acknowledge it spends real money (cap $5)")
    ap.add_argument("--budget-usd", type=float, default=DEFAULT_BUDGET_USD, help=f"whole-run budget (default {DEFAULT_BUDGET_USD}, max {HARD_CAP_USD})")
    ap.add_argument("--judge-model", default="", help="provider/model_name; skips candidate selection")
    ap.add_argument("--rate-in", type=float, default=None, help="USD per 1k input tokens for the judge model")
    ap.add_argument("--rate-out", type=float, default=None, help="USD per 1k output tokens for the judge model")
    ap.add_argument("--steps", default="", help="comma-separated step numbers (default all)")
    ap.add_argument("--keep-db", action="store_true", help="do not drop the canary_live_a database at the end")
    ap.add_argument("--env-file", default=str(MAIN_ENV_PATH), help="secrets file (real mode only)")
    return ap.parse_args(argv)


def say(msg: str) -> None:
    print(f"[livetest] {msg}", flush=True)


def _port_open(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def pick_judge(args: argparse.Namespace, secrets: Secrets, out_dir: Path, report: RunReport, spend: SpendGuard,
               make_env, run_doctor) -> tuple[tuple[str, str], Rates]:
    """Real mode: choose the judge model by pinging `cyber-rt doctor` with each candidate."""
    if args.judge_model:
        prov, _, model = args.judge_model.partition("/")
        cands = [(prov, model, args.rate_in if args.rate_in is not None else 0.003, args.rate_out if args.rate_out is not None else 0.015)]
    else:
        cands = CANDIDATES
    tried = []
    for prov, model, rin, rout in cands:
        doctor_ping_charge(spend, "preflight")
        ok, out = run_doctor(make_env((prov, model)))
        tried.append({"model": f"{prov}/{model}", "doctor_ok": ok})
        report.preflight.setdefault("doctor_output", {})[f"{prov}/{model}"] = secrets.scrub(out)[-1500:]
        if ok:
            report.models = {
                "judge": f"{prov}/{model}", "evaluator_ping": f"{prov}/{model}", "planner": "scripted (no LLM calls)",
                "judge_votes_k": 3,
                "rates_usd_per_1k": {"in": args.rate_in if args.rate_in is not None else rin, "out": args.rate_out if args.rate_out is not None else rout},
                "candidates_tried": tried,
                "model_list": "the code exposes no Backboard model list; candidates were pinged with `cyber-rt doctor`",
            }
            return (prov, model), Rates(args.rate_in if args.rate_in is not None else rin, args.rate_out if args.rate_out is not None else rout)
    raise StackError("no judge model passed `cyber-rt doctor`: " + ", ".join(t["model"] for t in tried))


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    dry = args.dry_run
    if not dry and not args.yes:
        print("Refusing a real run without --yes (it spends real Backboard money, capped at $5). Use --dry-run to test.", file=sys.stderr)
        return 2
    if not 0 < args.budget_usd <= HARD_CAP_USD:
        print(f"--budget-usd must be in (0, {HARD_CAP_USD}]", file=sys.stderr)
        return 2
    install_signal_handlers()
    run_id = time.strftime("%Y%m%d-%H%M%S") + ("-dry" if dry else "-real")
    out_dir = OUT / run_id
    report = RunReport(run_id=run_id, mode="dry-run" if dry else "real")
    caps = capabilities.detect()
    report.capabilities = caps.as_dict()
    t_run = time.time()

    # ---- secrets and preflight ------------------------------------------------------
    if dry:
        secrets = Secrets({})
        from cryptography.fernet import Fernet

        enc_key = Fernet.generate_key().decode()
        secrets.add_runtime("CANARY_ENCRYPTION_KEY", enc_key)
        secrets.add_runtime("DRYRUN_BACKBOARD_API_KEY", "dryrun-backboard-" + pysecrets.token_hex(12))
        report.preflight = {"secrets_file": "not read in dry-run", "wandb": "WANDB_MODE=disabled", "backboard": "fake LLM, unroutable base URL"}
    else:
        try:
            secrets = Secrets.from_file(Path(args.env_file))
        except MissingSecrets as exc:
            print(f"PREFLIGHT STOPPED: {exc}", file=sys.stderr)
            return 2
        status = secrets.status()
        report.preflight = {"secrets_file": str(args.env_file), "status": status}
        for name, st in status.items():
            say(f"secret {name}: {st}")
        missing = secrets.missing_required()
        if missing:
            print("PREFLIGHT STOPPED: these are empty or missing in the secrets file: " + ", ".join(missing)
                  + ". Fill them in and rerun. Nothing was started and nothing was spent.", file=sys.stderr)
            return 2
        enc_key = secrets.get("CANARY_ENCRYPTION_KEY") or ""
        if not enc_key:
            print("PREFLIGHT STOPPED: CANARY_ENCRYPTION_KEY is empty or missing.", file=sys.stderr)
            return 2

    judge_prompt_tokens = len((FOUNDRY / "prompts" / "judge.md").read_text(encoding="utf-8")) // 3
    spend = SpendGuard(budget_usd=args.budget_usd, judge_prompt_tokens=judge_prompt_tokens, dry_run=dry)
    if args.rate_in is not None and args.rate_out is not None:
        spend.rates = Rates(args.rate_in, args.rate_out)

    prepare_dirs(out_dir)
    from livetest.stack import WebhookCatcher

    stack: Stack | None = None
    ctx: Ctx | None = None
    interrupted = False
    try:
        catcher = WebhookCatcher()
        catcher.start()

        def make_env(judge):
            return build_env(dry_run=dry, secrets=secrets, enc_key=enc_key, out_dir=out_dir, catcher_port=catcher.port, judge=judge)

        def run_doctor(env):
            env = {**env, "NO_COLOR": "1", "COLUMNS": "300", "LOG_FILE": str(out_dir / "logs" / "doctor.app.log")}
            r = subprocess.run([str(Path(sys.executable).parent / "cyber-rt"), "doctor"], cwd=out_dir / "cwd", env=env,
                               capture_output=True, text=True, timeout=180)
            return r.returncode == 0, r.stdout + r.stderr

        if dry:
            judge = None
            report.models = {"judge": "dry-run fake judge (tests-style fake LLM, deterministic)", "planner": "scripted (no LLM calls)",
                             "judge_votes_k": 3, "rates_usd_per_1k_used_for_estimates": {"in": spend.rates.usd_per_1k_in, "out": spend.rates.usd_per_1k_out}}
        else:
            judge, rates = pick_judge(args, secrets, out_dir, report, spend, make_env, run_doctor)
            spend.rates = rates
        report.spend = spend.summary()

        stack = Stack(env_base=make_env(judge), dry_run=dry, out_dir=out_dir, keep_db=args.keep_db, catcher=catcher)
        say(f"starting stack ({report.mode}); out dir {out_dir}")
        stack.create_db()
        stack.migrate()
        keys = bootstrap_auth(stack, secrets)
        stack.start_api()
        stack.start_worker()
        say(f"api on {stack.api_base}; worker pid {stack.worker.popen.pid if stack.worker else '?'}")

        texts: list[str] = []
        ctx = Ctx(dry_run=dry, stack=stack, secrets=secrets, spend=spend, caps=caps, op=Api(stack.api_base, keys["operator_key"], texts),
                  admin=Api(stack.api_base, keys["admin_key"], texts), out_dir=out_dir, api_texts=texts)
        wanted = {int(x) for x in args.steps.split(",") if x.strip()} if args.steps else None
        for num, title, fn in STEPS:
            if wanted is not None and num not in wanted:
                continue
            res = StepResult(num, title)
            ctx.result = res
            t0 = time.time()
            say(f"step {num}: {title}")
            aborted = False
            try:
                if num in (2, 3, 7) and "main" not in ctx.targets:
                    raise RuntimeError("prerequisite failed: step 1 did not register the main target")
                fn(ctx)
            except KeyboardInterrupt:
                res.status, res.error = "error", "interrupted"
                raise
            except BudgetAbort as exc:
                res.status, res.error, aborted = "aborted", str(exc), True
                say(f"ABORT: {exc}")
            except Exception as exc:  # noqa: BLE001
                res.status = "error"
                res.error = secrets.scrub(f"{type(exc).__name__}: {exc}")[:400]
                res.notes.append(secrets.scrub("".join(traceback.format_exception_only(type(exc), exc)))[:300])
            finally:
                key = f"s{num}"
                try:
                    cids = ctx.state.get("step_cids", {}).get(key, [])
                    if cids or key in spend.held:
                        ctx.settle_judge(key, cids)
                except Exception as exc:  # noqa: BLE001
                    res.notes.append(f"spend settlement failed: {type(exc).__name__}")
                res.seconds = time.time() - t0
                res.spend_usd = spend.step_total(f"s{num}")
                res.finalize()
                report.steps.append(res)
                say(f"step {num} -> {res.status.upper()} ({res.seconds:.0f}s, ${res.spend_usd:.4f})")
            if aborted:
                break
    except KeyboardInterrupt:
        interrupted = True
        report.interrupted = True
        say("interrupted: tearing down")
        report.notes.append("run interrupted (Ctrl-C/SIGTERM); teardown executed")
    except (StackError, MissingSecrets) as exc:
        say(f"STACK ERROR: {secrets.scrub(str(exc))}")
        report.notes.append("stack error: " + secrets.scrub(str(exc))[:300])
        report.steps.append(StepResult(0, "Stack startup", status="error", error=secrets.scrub(str(exc))[:300]))
    finally:
        ports = []
        if stack is not None:
            ports = [stack.api_port] + [ft.port for ft in stack.fake_targets.values()] + ([stack.catcher.port] if stack.catcher else [])
            report.teardown = stack.teardown()
            time.sleep(0.5)
            report.teardown += [f"port {p} still open" for p in ports if p and _port_open(p)]
        report.spend = spend.summary()
        report.timings = {"total_s": round(time.time() - t_run, 1)}
        forbidden = list(secrets.sweep_values().values()) + [v for v in (secrets.get("WANDB_ENTITY"),) if v]
        try:
            md, js = report.write(out_dir / "report", forbidden)
            say(f"report: {md} and {js}")
        except RuntimeError as exc:
            say(str(exc))
    say(f"overall: {report.overall()}; spend charged ${spend.spent_usd:.4f} (estimated at real rates ${spend.would_spend_usd:.4f})")
    if interrupted:
        return 130
    return {"PASS": 0, "FAIL": 1, "ABORTED": 3}[report.overall()]


if __name__ == "__main__":
    sys.exit(main())
