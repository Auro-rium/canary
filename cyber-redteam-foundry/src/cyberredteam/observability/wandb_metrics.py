"""Campaign metrics on W&B Runs (WP11): implements ``hooks.CampaignMetrics``.

One ``wandb`` run per campaign (``job_type="campaign"``, ``id=campaign_id``,
``resume="allow"``).

Non-blocking by construction: every public method only enqueues work for ONE
background worker thread and returns immediately, so an unreachable W&B can
never stall a campaign, the API startup or an alert. The worker initialises
runs with a short ``init_timeout`` and a circuit breaker: after a failure all
W&B work is skipped for ``backoff_s`` seconds. ``self._lock`` guards only the
run dictionaries and is never held across a network call. Every run is created
with ``console="off"`` (no stdout/stderr capture), no git info and no code
saving. Nothing here raises into the caller.

``campaign_finished(summary)`` reads these optional keys:
  * ``technique_results``: list of dicts (technique, success_rate, ci_low, ci_high, ...)
  * ``verdict_counts``: ``{verdict: count}``
  * ``findings``: list of dicts (exported redacted)
  * ``report_json`` / ``report_markdown``: str or dict, logged as Artifact ``report-<id>``
  * ``headline``: ``{name: number | short text}`` copied to ``run.summary``
  * ``weave_url``: link back to the traces
Any other numeric top-level value is also copied to ``run.summary``.

``alert`` is for PLATFORM ops alerts (kill switch, Backboard error rate, budget
overrun) and goes to one global ops webhook. Per-target on-call notification is
WP3's ``EngineDeps.on_call`` / WP8's target webhook, not this module.
"""

from __future__ import annotations

import json
import logging
import queue
import re
import threading
import time
from collections.abc import Callable
from typing import Any

from cyberredteam.observability.redact import (
    mask_known,
    raw_export_allowed,
    redact_text,
    sanitize,
)

logger = logging.getLogger(__name__)

HttpPost = Callable[[str, dict[str, Any]], Any]
_SAFE_NAME = re.compile(r"[^A-Za-z0-9_.-]")
_TABLE_ROW_CAP = 500
_QUEUE_MAX = 2000


def _default_http_post(url: str, payload: dict[str, Any]) -> None:
    import httpx

    httpx.post(url, json=payload, timeout=5.0, follow_redirects=False, trust_env=False)


def _ssrf_guard(url: str) -> None:
    """The existing target SSRF guard: public http(s) hosts only (raises TargetRefused)."""
    from cyberredteam.security.ownership import check_target_url

    check_target_url(url)


class CircuitBreaker:
    """Opens for ``backoff_s`` after a failure; closed again on success."""

    def __init__(self, backoff_s: float = 300.0, clock: Callable[[], float] = time.monotonic):
        self.backoff_s, self._clock = backoff_s, clock
        self._open_until = 0.0
        self.failures = 0

    def allow(self) -> bool:
        return self._clock() >= self._open_until

    def fail(self) -> None:
        self.failures += 1
        self._open_until = self._clock() + self.backoff_s

    def ok(self) -> None:
        self._open_until = 0.0


class WandbCampaignMetrics:
    def __init__(
        self,
        project: str = "canary",
        entity: str | None = None,
        mode: str | None = None,
        directory: str | None = None,
        oncall_webhook_url: str | None = None,
        http_post: HttpPost | None = None,
        url_check: Callable[[str], None] | None = None,
        wandb_module: Any = None,
        init_timeout_s: float = 5.0,
        backoff_s: float = 300.0,
    ) -> None:
        self.project, self.entity, self.mode, self.directory = project, entity, mode, directory
        self.oncall_webhook_url = oncall_webhook_url  # global ops webhook
        self._http_post = http_post or _default_http_post
        self._url_check = url_check or _ssrf_guard
        self._hook_pool: Any = None
        self._hook_futures: list[Any] = []
        self._wandb = wandb_module
        self.init_timeout_s = init_timeout_s
        self.breaker = CircuitBreaker(backoff_s)
        self._runs: dict[str, Any] = {}
        self._envs: dict[str, str] = {}
        self._service_run: Any = None
        self.service_failed = False
        self._lock = threading.Lock()  # dict access only, never held across I/O
        self._q: queue.Queue[Callable[[], None] | None] = queue.Queue(_QUEUE_MAX)
        self._worker: threading.Thread | None = None
        self._worker_lock = threading.Lock()
        self.disabled = False

    # ── worker plumbing ─────────────────────────────────────────────────────

    def _submit(self, job: Callable[[], None]) -> None:
        try:
            with self._worker_lock:
                if self._worker is None:
                    self._worker = threading.Thread(
                        target=self._run_worker, name="canary-wandb", daemon=True
                    )
                    self._worker.start()
            self._q.put_nowait(job)
        except queue.Full:
            logger.warning("wandb queue full, dropping a telemetry event")
        except Exception as exc:
            logger.warning("wandb submit failed: %s", exc)

    def _run_worker(self) -> None:
        while True:
            job = self._q.get()
            try:
                if job is None:
                    return
                job()
            except Exception as exc:
                logger.warning("wandb job failed: %s", exc)
            finally:
                self._q.task_done()

    def flush(self, timeout: float = 30.0) -> bool:
        """Wait until queued work is done (tests / shutdown). True if drained."""
        deadline = time.monotonic() + timeout
        for fut in list(self._hook_futures):
            try:
                fut.result(max(0.0, deadline - time.monotonic()))
            except Exception:
                pass
        while self._q.unfinished_tasks and time.monotonic() < deadline:
            time.sleep(0.01)
        return not self._q.unfinished_tasks

    def _sdk(self) -> Any | None:
        if self._wandb is not None:
            return self._wandb
        if self.disabled or (self.mode or "").lower() == "disabled":
            return None
        try:
            import wandb

            self._wandb = wandb
            return wandb
        except Exception:
            self.disabled = True
            return None

    def _init_run(self, **kwargs: Any) -> Any | None:
        """Worker-thread only. None when W&B is unavailable or the breaker is open."""
        sdk = self._sdk()
        if sdk is None or not self.breaker.allow():
            return None
        kwargs.setdefault("project", self.project)
        if self.entity:
            kwargs.setdefault("entity", self.entity)
        if self.directory:
            kwargs.setdefault("dir", self.directory)
        settings_kw: dict[str, Any] = {
            "console": "off",  # never upload stdout/stderr (may carry evidence)
            "disable_git": True,
            "save_code": False,
            "init_timeout": self.init_timeout_s,
        }
        if self.mode:
            settings_kw["mode"] = self.mode
        try:
            settings = sdk.Settings(**settings_kw)
        except Exception:
            settings = None
        if settings is not None:
            kwargs["settings"] = settings
        try:
            try:
                run = sdk.init(reinit="create_new", **kwargs)
            except TypeError:  # older wandb: no reinit="create_new"
                run = sdk.init(reinit=True, **kwargs)
        except Exception as exc:
            self.breaker.fail()
            logger.warning(
                "wandb init failed (%s); pausing W&B for %ds", type(exc).__name__,
                int(self.breaker.backoff_s),
            )
            return None
        self.breaker.ok()
        return run

    # ── CampaignMetrics ─────────────────────────────────────────────────────

    def campaign_started(self, campaign_id: str, config: dict[str, Any]) -> None:
        self._submit(lambda: self._do_started(campaign_id, config))

    def _do_started(self, campaign_id: str, config: dict[str, Any]) -> None:
        with self._lock:
            if campaign_id in self._runs:
                return
            self._envs[campaign_id] = str((config or {}).get("environment", "production")).lower()
        run = self._init_run(
            job_type="campaign",
            id=_SAFE_NAME.sub("_", campaign_id),
            resume="allow",
            name=f"campaign-{campaign_id}"[:128],
            config=sanitize(config, raw=False, hashes=False) if config else {},
        )
        if run is not None:
            with self._lock:
                self._runs[campaign_id] = run

    def log(self, campaign_id: str, metrics: dict[str, float], step: int | None = None) -> None:
        clean = {
            str(k)[:100]: float(v)
            for k, v in (metrics or {}).items()
            if isinstance(v, (int, float)) and not isinstance(v, bool)
        }
        if not clean:
            return
        self._submit(lambda: self._do_log(campaign_id, clean, step))

    def _do_log(self, campaign_id: str, clean: dict[str, float], step: int | None) -> None:
        with self._lock:
            run = self._runs.get(campaign_id)
        if run is None:
            return
        if step is not None:
            run.log(clean, step=step)
        else:
            run.log(clean)

    def campaign_finished(self, campaign_id: str, summary: dict[str, Any]) -> None:
        self._submit(lambda: self._do_finished(campaign_id, summary))

    def _do_finished(self, campaign_id: str, summary: dict[str, Any]) -> None:
        with self._lock:
            run = self._runs.pop(campaign_id, None)
            env = self._envs.pop(campaign_id, "production")
        if run is None:
            return
        try:
            self._write_final(run, campaign_id, summary or {}, env)
        finally:
            try:
                run.finish()
            except Exception as exc:
                logger.warning("wandb finish failed: %s", exc)

    def _write_final(self, run: Any, campaign_id: str, summary: dict[str, Any], env: str) -> None:
        sdk = self._sdk()
        raw = raw_export_allowed(env)
        try:
            techniques = list(summary.get("technique_results") or [])[:_TABLE_ROW_CAP]
            if techniques:
                cols = ["technique", "success_rate", "ci_low", "ci_high", "trials", "successes"]
                rows = [
                    [sanitize(t.get("technique"), raw=False, hashes=False), t.get("success_rate"),
                     t.get("ci_low"), t.get("ci_high"), t.get("trials"), t.get("successes")]
                    for t in techniques
                ]
                run.log({"technique_results": sdk.Table(columns=cols, data=rows)})
            verdicts = summary.get("verdict_counts") or {}
            if verdicts:
                vt = sdk.Table(columns=["verdict", "count"],
                               data=[[redact_text(str(k), False)[:60], v]
                                     for k, v in verdicts.items()])
                payload: dict[str, Any] = {"verdict_counts": vt}
                try:
                    payload["verdict_summary"] = sdk.plot.bar(vt, "verdict", "count",
                                                              title="Verdict summary")
                except Exception:
                    pass
                run.log(payload)
            findings = list(summary.get("findings") or [])[:_TABLE_ROW_CAP]
            if findings:
                red = [sanitize(f, raw=raw) for f in findings]  # keys are redacted too
                cols = sorted({k for f in red if isinstance(f, dict) for k in f})
                data = [[f.get(c) if isinstance(f, dict) else None for c in cols] for f in red]
                run.log({"findings": sdk.Table(columns=cols, data=data)})
        except Exception as exc:
            logger.warning("wandb tables failed: %s", exc)

        try:
            self._log_report(run, campaign_id, summary, raw)
        except Exception as exc:
            logger.warning("wandb report artifact failed: %s", exc)

        try:
            for k, v in (summary.get("headline") or {}).items():
                key = redact_text(str(k), False)[:100]
                if isinstance(v, (int, float)) and not isinstance(v, bool):
                    run.summary[key] = v
                elif isinstance(v, str):
                    run.summary[key] = sanitize(v, raw=False)
            for k, v in summary.items():
                if isinstance(v, (int, float)) and not isinstance(v, bool) and k not in run.summary:
                    run.summary[k] = v
            if summary.get("weave_url"):
                run.summary["weave_url"] = mask_known(str(summary["weave_url"]))
        except Exception as exc:
            logger.warning("wandb summary failed: %s", exc)

    def _log_report(self, run: Any, campaign_id: str, summary: dict[str, Any], raw: bool) -> None:
        rj, rm = summary.get("report_json"), summary.get("report_markdown")
        if rj is None and rm is None:
            return
        sdk = self._sdk()
        art = sdk.Artifact(f"report-{_SAFE_NAME.sub('_', campaign_id)}", type="report")
        if rj is not None:
            body = rj if isinstance(rj, str) else json.dumps(rj, default=str)
            with art.new_file("report.json", "w") as fh:
                fh.write(self._report_text(body, raw))
        if rm is not None:
            with art.new_file("report.md", "w") as fh:
                fh.write(self._report_text(str(rm), raw))
        run.log_artifact(art)

    @staticmethod
    def _report_text(text: str, raw: bool) -> str:
        if raw:
            return mask_known(text)
        return redact_text(text)  # bounded prefix; fail closed to a hash marker

    def alert(self, title: str, text: str, level: str = "WARN") -> None:
        """Platform ops alert: W&B alert (async) + global ops webhook."""
        title_r, text_r = sanitize_alert(title), sanitize_alert(text)
        self._submit(lambda: self._do_alert(title_r, text_r, level))
        if self.oncall_webhook_url:
            payload = {"title": title_r, "text": text_r, "level": level.upper(), "ts": time.time()}
            self._submit_webhook(self.oncall_webhook_url, payload)

    def _submit_webhook(self, url: str, payload: dict[str, Any]) -> None:
        """Send off-thread (DNS/HTTP may block); the SSRF guard runs first."""
        try:
            from concurrent.futures import ThreadPoolExecutor

            with self._worker_lock:
                if self._hook_pool is None:
                    self._hook_pool = ThreadPoolExecutor(1, thread_name_prefix="canary-ops-hook")
                fut = self._hook_pool.submit(self._send_webhook, url, payload)
                self._hook_futures = [f for f in self._hook_futures if not f.done()] + [fut]
        except Exception as exc:
            logger.warning("ops webhook submit failed: %s", exc)

    def _send_webhook(self, url: str, payload: dict[str, Any]) -> None:
        try:
            self._url_check(url)
        except Exception as exc:
            logger.warning("ops webhook refused by SSRF guard: %s", exc)
            return
        try:
            self._http_post(url, payload)
        except Exception as exc:
            logger.warning("ops webhook failed: %s", type(exc).__name__)

    def _do_alert(self, title: str, text: str, level: str) -> None:
        sdk = self._sdk()
        with self._lock:
            run = self._service_run or next(iter(self._runs.values()), None)
        if sdk is None or run is None:
            return
        lvl = getattr(sdk.AlertLevel, level.upper(), sdk.AlertLevel.WARN)
        run.alert(title=title, text=text, level=lvl)

    # ── Service run ─────────────────────────────────────────────────────────

    def service_started(self, service_name: str, config: dict[str, Any] | None = None) -> None:
        self._submit(lambda: self._do_service_started(service_name, config))

    def _do_service_started(self, service_name: str, config: dict[str, Any] | None) -> None:
        with self._lock:
            if self._service_run is not None:
                return
        run = self._init_run(
            job_type="service", name=f"service-{service_name}"[:128],
            config=sanitize(config or {}, raw=False, hashes=False),
        )
        with self._lock:
            self._service_run = run
        self.service_failed = run is None

    def service_log(self, metrics: dict[str, float]) -> None:
        clean = {str(k)[:100]: float(v) for k, v in metrics.items()
                 if isinstance(v, (int, float)) and not isinstance(v, bool)}
        if clean:
            self._submit(lambda: self._do_service_log(clean))

    def _do_service_log(self, clean: dict[str, float]) -> None:
        with self._lock:
            run = self._service_run
        if run is not None:
            run.log(clean)

    def close(self) -> None:
        self.flush(5.0)
        with self._lock:
            runs = list(self._runs.values()) + ([self._service_run] if self._service_run else [])
            self._runs.clear()
            self._service_run = None
        for r in runs:
            try:
                r.finish()
            except Exception:
                pass


def sanitize_alert(text: str) -> str:
    """Alert text carries no evidence by contract; still redact a bounded prefix."""
    return redact_text(text, fail_closed=False)[:500]
