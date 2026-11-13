"""Campaign metrics on W&B Runs (WP11): implements ``hooks.CampaignMetrics``.

One ``wandb`` run per campaign (``job_type="campaign"``, ``id=campaign_id``,
``resume="allow"``). Thread-safe; every public method swallows its own errors
so a W&B outage never reaches the campaign path.

``campaign_finished(summary)`` reads these optional keys:
  * ``technique_results``: list of dicts (technique, success_rate, ci_low, ci_high, ...)
  * ``verdict_counts``: ``{verdict: count}``
  * ``findings``: list of dicts (exported redacted)
  * ``report_json`` / ``report_markdown``: str or dict, logged as Artifact ``report-<id>``
  * ``headline``: ``{name: number}`` copied to ``run.summary``
  * ``weave_url``: link back to the traces
Any other scalar top-level value is also copied to ``run.summary``.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from collections.abc import Callable
from typing import Any

from cyberredteam.observability.redact import raw_export_allowed, sanitize

logger = logging.getLogger(__name__)

HttpPost = Callable[[str, dict[str, Any]], Any]
_SAFE_NAME = re.compile(r"[^A-Za-z0-9_.-]")
_TABLE_ROW_CAP = 500


def _default_http_post(url: str, payload: dict[str, Any]) -> None:
    import httpx

    def _go() -> None:
        try:
            httpx.post(url, json=payload, timeout=5.0)
        except Exception as exc:
            logger.warning("on-call webhook failed: %s", exc)

    threading.Thread(target=_go, daemon=True).start()


class WandbCampaignMetrics:
    def __init__(
        self,
        project: str = "canary",
        entity: str | None = None,
        mode: str | None = None,
        directory: str | None = None,
        oncall_webhook_url: str | None = None,
        http_post: HttpPost | None = None,
        wandb_module: Any = None,
    ) -> None:
        self.project, self.entity, self.mode, self.directory = project, entity, mode, directory
        self.oncall_webhook_url = oncall_webhook_url
        self._http_post = http_post or _default_http_post
        self._wandb = wandb_module
        self._runs: dict[str, Any] = {}
        self._envs: dict[str, str] = {}
        self._service_run: Any = None
        self._lock = threading.RLock()
        self.disabled = False

    # ── plumbing ────────────────────────────────────────────────────────────

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
        sdk = self._sdk()
        if sdk is None:
            return None
        kwargs.setdefault("project", self.project)
        if self.entity:
            kwargs.setdefault("entity", self.entity)
        if self.mode:
            kwargs.setdefault("mode", self.mode)
        if self.directory:
            kwargs.setdefault("dir", self.directory)
        try:
            return sdk.init(reinit="create_new", **kwargs)
        except TypeError:  # older wandb: no reinit="create_new"
            return sdk.init(reinit=True, **kwargs)

    # ── CampaignMetrics ─────────────────────────────────────────────────────

    def campaign_started(self, campaign_id: str, config: dict[str, Any]) -> None:
        try:
            with self._lock:
                if campaign_id in self._runs:
                    return
                self._envs[campaign_id] = str(config.get("environment", "production")).lower()
                run = self._init_run(
                    job_type="campaign",
                    id=_SAFE_NAME.sub("_", campaign_id),
                    resume="allow",
                    name=f"campaign-{campaign_id}"[:128],
                    config=sanitize(config, raw=False) if config else {},
                )
                if run is not None:
                    self._runs[campaign_id] = run
        except Exception as exc:
            logger.warning("wandb campaign_started failed: %s", exc)

    def log(self, campaign_id: str, metrics: dict[str, float], step: int | None = None) -> None:
        try:
            with self._lock:
                run = self._runs.get(campaign_id)
                if run is None:
                    return
                run.log(dict(metrics), step=step) if step is not None else run.log(dict(metrics))
        except Exception as exc:
            logger.warning("wandb log failed: %s", exc)

    def campaign_finished(self, campaign_id: str, summary: dict[str, Any]) -> None:
        try:
            with self._lock:
                run = self._runs.pop(campaign_id, None)
                env = self._envs.pop(campaign_id, "production")
            if run is None:
                return
            try:
                self._write_final(run, campaign_id, summary, env)
            finally:
                try:
                    run.finish()
                except Exception as exc:
                    logger.warning("wandb finish failed: %s", exc)
        except Exception as exc:
            logger.warning("wandb campaign_finished failed: %s", exc)

    def _write_final(self, run: Any, campaign_id: str, summary: dict[str, Any], env: str) -> None:
        sdk = self._sdk()
        raw = raw_export_allowed(env)
        try:
            techniques = list(summary.get("technique_results") or [])[:_TABLE_ROW_CAP]
            if techniques:
                cols = ["technique", "success_rate", "ci_low", "ci_high", "trials", "successes"]
                rows = [[t.get("technique"), t.get("success_rate"), t.get("ci_low"),
                         t.get("ci_high"), t.get("trials"), t.get("successes")] for t in techniques]
                run.log({"technique_results": sdk.Table(columns=cols, data=rows)})
            verdicts = summary.get("verdict_counts") or {}
            if verdicts:
                vt = sdk.Table(columns=["verdict", "count"],
                               data=[[str(k), v] for k, v in verdicts.items()])
                payload: dict[str, Any] = {"verdict_counts": vt}
                try:
                    payload["verdict_summary"] = sdk.plot.bar(vt, "verdict", "count",
                                                              title="Verdict summary")
                except Exception:
                    pass
                run.log(payload)
            findings = list(summary.get("findings") or [])[:_TABLE_ROW_CAP]
            if findings:
                red = [sanitize(f, raw=raw) for f in findings]
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
                run.summary[k] = v
            for k, v in summary.items():
                if isinstance(v, (int, float, bool)) and k not in run.summary:
                    run.summary[k] = v
            if summary.get("weave_url"):
                run.summary["weave_url"] = str(summary["weave_url"])
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
            return text
        from cyberredteam.observability.redact import redact_text

        return redact_text(text)  # fail closed: a hash marker if no redactor

    def alert(self, title: str, text: str, level: str = "WARN") -> None:
        title_r, text_r = sanitize_alert(title), sanitize_alert(text)
        try:
            sdk = self._sdk()
            with self._lock:
                run = self._service_run or next(iter(self._runs.values()), None)
            if sdk is not None and run is not None:
                lvl = getattr(sdk.AlertLevel, level.upper(), sdk.AlertLevel.WARN)
                run.alert(title=title_r, text=text_r, level=lvl)
        except Exception as exc:
            logger.warning("wandb alert failed: %s", exc)
        if self.oncall_webhook_url:
            try:
                self._http_post(self.oncall_webhook_url,
                                {"title": title_r, "text": text_r, "level": level.upper(),
                                 "ts": time.time()})
            except Exception as exc:
                logger.warning("on-call webhook failed: %s", exc)

    # ── Service run ─────────────────────────────────────────────────────────

    def service_started(self, service_name: str, config: dict[str, Any] | None = None) -> None:
        try:
            with self._lock:
                if self._service_run is None:
                    self._service_run = self._init_run(
                        job_type="service", name=f"service-{service_name}"[:128],
                        config=sanitize(config or {}, raw=False),
                    )
        except Exception as exc:
            logger.warning("wandb service_started failed: %s", exc)

    def service_log(self, metrics: dict[str, float]) -> None:
        try:
            with self._lock:
                if self._service_run is not None:
                    self._service_run.log(dict(metrics))
        except Exception as exc:
            logger.warning("wandb service_log failed: %s", exc)

    def close(self) -> None:
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
    from cyberredteam.observability.redact import redact_text

    return redact_text(text, fail_closed=False)[:500]
