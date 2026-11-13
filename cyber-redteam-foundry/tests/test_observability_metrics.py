"""WP11: wandb campaign metrics (offline, never network) and failure isolation."""

from pathlib import Path

import pytest

from cyberredteam.observability import hooks, redact
from cyberredteam.observability.setup import init_observability, reset_for_tests
from cyberredteam.observability.wandb_metrics import WandbCampaignMetrics

SUMMARY = {
    "technique_results": [
        {"technique": "role_play", "success_rate": 0.25, "ci_low": 0.05, "ci_high": 0.6,
         "trials": 8, "successes": 2}
    ],
    "verdict_counts": {"safe": 6, "unsafe": 2},
    "findings": [{"id": "f1", "title": "leak", "evidence": "mail bob@example.com"}],
    "report_json": {"campaign": "c-1", "n": 1},
    "report_markdown": "# Report",
    "headline": {"asr": 0.25, "critical_findings": 1},
}


def test_offline_run_has_metrics_tables_and_report_artifact(tmp_path, monkeypatch):
    pytest.importorskip("wandb")
    monkeypatch.setenv("WANDB_SILENT", "true")
    m = WandbCampaignMetrics(project="canary-test", mode="offline", directory=str(tmp_path))
    m.campaign_started("c-1", {"environment": "production", "policy": {"max_turns": 5},
                               "headers": {"Authorization": "Bearer abcdefghijklmnopqrstuv"},
                               "api_key": "sk-should-not-appear"})
    assert "c-1" in m._runs, "offline wandb run was not created"
    for step in range(1, 4):
        m.log("c-1", {"turns_total": float(step), "llm_cost_usd": 0.01 * step}, step=step)
    run_dir = Path(m._runs["c-1"].dir).parent
    m.campaign_finished("c-1", SUMMARY)
    assert "c-1" not in m._runs

    files = [p for p in tmp_path.rglob("*") if p.is_file()]
    names = " ".join(str(p) for p in files)
    assert any(p.suffix == ".wandb" for p in files)  # offline run record
    assert run_dir.exists()
    text = ""
    for p in files:
        if p.stat().st_size < 5_000_000:
            text += p.read_bytes().decode("utf-8", "ignore")
    assert "sk-should-not-appear" not in text
    assert "abcdefghijklmnopqrstuv" not in text
    assert "bob@example.com" not in text
    for needle in ("turns_total", "technique_results", "report-c-1", "role_play"):
        assert needle in text or needle in names, needle


class FakeRun:
    def __init__(self):
        self.logged, self.summary, self.alerts, self.finished = [], {}, [], False
        self.artifacts = []

    def log(self, data, step=None):
        self.logged.append((data, step))

    def alert(self, **kw):
        self.alerts.append(kw)

    def log_artifact(self, art):
        self.artifacts.append(art)

    def finish(self):
        self.finished = True


class FakeArtifact:
    def __init__(self, name, type):
        self.name, self.files = name, {}

    def new_file(self, name, mode="w"):
        import io

        files = self.files

        class Buf(io.StringIO):
            def close(self):
                files[name] = self.getvalue()
                super().close()

        return Buf()


class FakeWandb:
    class AlertLevel:
        WARN, ERROR, INFO = "WARN", "ERROR", "INFO"

    Artifact = FakeArtifact

    class Table:
        def __init__(self, columns, data):
            self.columns, self.data = columns, data

    plot = None

    def __init__(self):
        self.run = FakeRun()

    def init(self, **kw):
        self.kw = kw
        return self.run


def test_fake_sdk_flow_redacts_findings_and_names_artifact():
    sdk = FakeWandb()
    m = WandbCampaignMetrics(wandb_module=sdk)
    m.campaign_started("camp/1", {"environment": "production"})
    assert sdk.kw["job_type"] == "campaign" and sdk.kw["resume"] == "allow"
    m.log("camp/1", {"turns_total": 1.0}, step=1)
    m.campaign_finished("camp/1", SUMMARY)
    run = sdk.run
    assert run.logged[0] == ({"turns_total": 1.0}, 1)
    tables = {k: v for d, _ in run.logged for k, v in d.items()}
    assert "technique_results" in tables and "findings" in tables
    assert "bob@example.com" not in repr(tables["findings"].data)
    assert run.artifacts[0].name == "report-camp_1"
    assert run.summary["asr"] == 0.25 and run.finished


def test_wandb_unreachable_never_raises():
    class Down:
        def init(self, **kw):
            raise ConnectionError("wandb down")

    m = WandbCampaignMetrics(wandb_module=Down())
    m.campaign_started("c", {})
    m.log("c", {"x": 1.0}, step=1)
    m.campaign_finished("c", SUMMARY)
    m.alert("t", "x")
    m.service_started("api")
    m.service_log({"a": 1.0})


def test_failing_run_methods_never_raise():
    class BadRun(FakeRun):
        def log(self, *a, **k):
            raise RuntimeError("boom")

        def finish(self):
            raise RuntimeError("boom")

    sdk = FakeWandb()
    sdk.run = BadRun()
    m = WandbCampaignMetrics(wandb_module=sdk)
    m.campaign_started("c", {})
    m.log("c", {"x": 1.0}, step=1)
    m.campaign_finished("c", SUMMARY)


def test_alert_sends_wandb_alert_and_webhook():
    sdk, posted = FakeWandb(), []
    m = WandbCampaignMetrics(wandb_module=sdk, oncall_webhook_url="https://oncall.test/h",
                             http_post=lambda url, payload: posted.append((url, payload)))
    m.campaign_started("c", {})
    m.alert("Critical finding", "leak in prod", "ERROR")
    assert sdk.run.alerts[0]["level"] == "ERROR"
    assert posted[0][0] == "https://oncall.test/h" and posted[0][1]["level"] == "ERROR"


def test_webhook_failure_is_swallowed():
    def bad(url, payload):
        raise OSError("net")

    WandbCampaignMetrics(wandb_module=FakeWandb(), oncall_webhook_url="https://x",
                         http_post=bad).alert("t", "x")


def test_init_observability_is_noop_without_key_or_when_disabled():
    class S:
        wandb_api_key = None
        wandb_mode = "online"
        wandb_entity = None
        wandb_project = "canary"
        wandb_export_raw_evidence = False

    class D(S):
        wandb_mode = "disabled"
        wandb_api_key = "k"

    reset_for_tests()
    try:
        h = init_observability(S())
        assert not h.enabled and isinstance(hooks.get_metrics(), hooks.NoopMetrics)
        reset_for_tests()
        assert not init_observability(D()).enabled
    finally:
        reset_for_tests()
        redact.configure_raw_export(False)
        redact._known_secrets.clear()
