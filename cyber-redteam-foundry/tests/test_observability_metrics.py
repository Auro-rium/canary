"""WP11: wandb campaign metrics (offline, never network) and failure isolation."""

import time
from pathlib import Path

import pytest

from cyberredteam.observability import hooks, redact
from cyberredteam.observability.setup import init_observability, reset_for_tests
from cyberredteam.observability.wandb_metrics import WandbCampaignMetrics

SSN = "123-45-6789"
EMAIL = "dana.private@example-corp.com"

SUMMARY = {
    "technique_results": [
        {"technique": "role_play", "success_rate": 0.25, "ci_low": 0.05, "ci_high": 0.6,
         "trials": 8, "successes": 2}
    ],
    "verdict_counts": {"safe": 6, "unsafe": 2},
    "findings": [{"id": "f1", "title": "leak", "evidence": f"mail {EMAIL} ssn {SSN}",
                  f"note for {EMAIL}": "x"}],
    "report_json": {"campaign": "c-1", "n": 1},
    "report_markdown": f"# Report\nvictim {EMAIL}",
    "headline": {"asr": 0.25, "critical_findings": 1, "note": f"see {EMAIL}"},
}


def _all_text(root: Path) -> tuple[str, str]:
    files = [p for p in root.rglob("*") if p.is_file() and p.stat().st_size < 5_000_000]
    names = " ".join(str(p) for p in files)
    text = "".join(p.read_bytes().decode("utf-8", "ignore") for p in files)
    return names, text


def test_offline_run_has_metrics_tables_and_report_artifact(tmp_path):
    pytest.importorskip("wandb")
    m = WandbCampaignMetrics(project="canary-test", mode="offline", directory=str(tmp_path))
    m.campaign_started("c-1", {"environment": "production", "policy": {"max_turns": 5},
                               "headers": {"Authorization": "Bearer abcdefghijklmnopqrstuv"},
                               "api_key": "sk-should-not-appear",
                               "endpoint": "https://t.example.com/chat?token=querysecret123"})
    for step in range(1, 4):
        m.log("c-1", {"turns_total": float(step), "llm_cost_usd": 0.01 * step, "bad": "str"},
              step=step)
    m.campaign_finished("c-1", SUMMARY)
    assert m.flush(60)

    names, text = _all_text(tmp_path)
    assert any(p.suffix == ".wandb" for p in tmp_path.rglob("*"))  # offline run record
    for leaked in ("sk-should-not-appear", "abcdefghijklmnopqrstuv", EMAIL, SSN,
                   "querysecret123", "dana.private"):
        assert leaked not in text, leaked
    for needle in ("turns_total", "technique_results", "report-c-1", "role_play"):
        assert needle in text or needle in names, needle


def test_console_output_is_not_captured(tmp_path):
    pytest.importorskip("wandb")
    m = WandbCampaignMetrics(project="canary-test", mode="offline", directory=str(tmp_path))
    m.campaign_started("c-console", {"environment": "production"})
    m.service_started("api")
    assert m.flush(60)
    print(f"stdout carrying PII {EMAIL} {SSN} CONSOLE-CANARY-1")
    import sys

    print(f"stderr carrying PII {EMAIL} CONSOLE-CANARY-2", file=sys.stderr)
    m.log("c-console", {"x": 1.0}, step=1)
    m.campaign_finished("c-console", {})
    m.close()
    outputs = list(tmp_path.rglob("output.log"))
    assert all(p.stat().st_size == 0 for p in outputs), outputs
    _, text = _all_text(tmp_path)
    assert "CONSOLE-CANARY" not in text and EMAIL not in text


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

    class Settings:
        def __init__(self, **kw):
            self.kw = kw

    plot = None

    def __init__(self):
        self.run = FakeRun()
        self.kw = {}

    def init(self, **kw):
        self.kw = kw
        return self.run


def test_every_init_disables_console_git_and_code_capture():
    sdk = FakeWandb()
    m = WandbCampaignMetrics(wandb_module=sdk)
    m.campaign_started("c", {})
    assert m.flush(5)
    s = sdk.kw["settings"].kw
    assert s["console"] == "off" and s["disable_git"] is True and s["save_code"] is False
    assert s["init_timeout"] <= 10
    sdk2 = FakeWandb()
    m2 = WandbCampaignMetrics(wandb_module=sdk2)
    m2.service_started("api")
    assert m2.flush(5)
    assert sdk2.kw["settings"].kw["console"] == "off" and sdk2.kw["job_type"] == "service"


def test_fake_sdk_flow_redacts_findings_columns_and_report():
    sdk = FakeWandb()
    m = WandbCampaignMetrics(wandb_module=sdk)
    m.campaign_started("camp/1", {"environment": "production"})
    m.log("camp/1", {"turns_total": 1.0, "label": "x", "flag": True}, step=1)
    m.campaign_finished("camp/1", SUMMARY)
    assert m.flush(5)
    run = sdk.run
    assert sdk.kw["job_type"] == "campaign" and sdk.kw["resume"] == "allow"
    assert run.logged[0] == ({"turns_total": 1.0}, 1)  # non-numeric values dropped
    tables = {k: v for d, _ in run.logged for k, v in d.items()}
    dumped = repr([(t.columns, t.data) for t in tables.values() if hasattr(t, "columns")])
    for leaked in (EMAIL, SSN, "dana.private"):
        assert leaked not in dumped  # includes column names
    assert run.artifacts[0].name == "report-camp_1"
    assert EMAIL not in repr(run.artifacts[0].files)
    assert run.summary["asr"] == 0.25 and EMAIL not in repr(run.summary) and run.finished


def test_raw_report_still_masks_known_secrets():
    redact.register_secret("TOPSECRETVALUE-xyz")
    redact.configure_raw_export(True)
    try:
        sdk = FakeWandb()
        m = WandbCampaignMetrics(wandb_module=sdk)
        m.campaign_started("c", {"environment": "staging"})
        m.campaign_finished("c", {"report_markdown": "leak TOPSECRETVALUE-xyz here"})
        assert m.flush(5)
        assert "TOPSECRETVALUE" not in repr(sdk.run.artifacts[0].files)
    finally:
        redact.configure_raw_export(False)
        redact._known_secrets.clear()


def test_wandb_unreachable_never_raises_and_trips_breaker():
    class Down:
        calls = 0

        class Settings:
            def __init__(self, **kw):
                pass

        def init(self, **kw):
            Down.calls += 1
            raise ConnectionError("wandb down")

    m = WandbCampaignMetrics(wandb_module=Down())
    m.campaign_started("c", {})
    m.log("c", {"x": 1.0}, step=1)
    m.campaign_finished("c", SUMMARY)
    m.alert("t", "x")
    m.service_started("api")
    m.service_log({"a": 1.0})
    assert m.flush(5)
    assert Down.calls == 1  # breaker open: later inits are skipped, not retried
    assert m.service_failed


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
    assert m.flush(5)


def test_alert_sends_wandb_alert_and_ops_webhook_without_pii():
    sdk, posted = FakeWandb(), []
    m = WandbCampaignMetrics(wandb_module=sdk, oncall_webhook_url="https://ops.test/h",
                             http_post=lambda url, payload: posted.append((url, payload)),
                             url_check=lambda url: None)
    m.campaign_started("c", {})
    assert m.flush(5)
    m.alert("Kill switch", f"engaged; contact {EMAIL} ssn {SSN} Bearer abcdefghijklmnopqrstuv",
            "ERROR")
    assert m.flush(5)
    url, payload = posted[0]
    assert url == "https://ops.test/h" and payload["level"] == "ERROR"
    body = repr(payload) + repr(sdk.run.alerts)
    for leaked in (EMAIL, SSN, "abcdefghijklmnopqrstuv"):
        assert leaked not in body
    assert sdk.run.alerts[0]["level"] == "ERROR"


def test_webhook_failure_is_swallowed():
    def bad(url, payload):
        raise OSError("net")

    m = WandbCampaignMetrics(wandb_module=FakeWandb(), oncall_webhook_url="https://x",
                             http_post=bad, url_check=lambda url: None)
    m.alert("t", "x")
    assert m.flush(5)


@pytest.mark.parametrize("url", ["http://127.0.0.1:8080/h", "http://169.254.169.254/x",
                                 "http://localhost/h", "ftp://example.com/h"])
def test_ops_webhook_passes_through_ssrf_guard(url):
    posted = []
    m = WandbCampaignMetrics(wandb_module=FakeWandb(), oncall_webhook_url=url,
                             http_post=lambda u, p: posted.append(u))  # default real guard
    m.alert("Kill switch", "engaged", "ERROR")
    assert m.flush(5)
    assert posted == []


def test_settings_exposes_ops_webhook_url():
    from cyberredteam.settings import Settings

    assert Settings(canary_ops_webhook_url="https://ops.example.com/h").canary_ops_webhook_url


class _S:
    wandb_api_key = None
    wandb_mode = "online"
    wandb_entity = None
    wandb_project = "canary"
    wandb_export_raw_evidence = False


@pytest.fixture
def clean_obs():
    reset_for_tests()
    yield
    reset_for_tests()
    redact.configure_raw_export(False)
    redact._known_secrets.clear()


def test_init_observability_is_noop_without_key_or_when_disabled(clean_obs):
    h = init_observability(_S())
    assert not h.enabled and isinstance(hooks.get_metrics(), hooks.NoopMetrics)
    reset_for_tests()

    class D(_S):
        wandb_mode = "disabled"
        wandb_api_key = "k"

    assert not init_observability(D()).enabled


def test_unreachable_wandb_does_not_block_startup_campaign_or_alert(clean_obs, monkeypatch):
    pytest.importorskip("wandb")
    monkeypatch.setenv("WANDB_BASE_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("WANDB_API_KEY", "x" * 40)

    class U(_S):
        wandb_api_key = "x" * 40

    t0 = time.perf_counter()
    h = init_observability(U())
    assert time.perf_counter() - t0 < 1.0
    m = hooks.get_metrics()
    assert m is h.metrics
    t0 = time.perf_counter()
    m.campaign_started("c-unreach", {"environment": "production"})
    m.log("c-unreach", {"x": 1.0}, step=1)
    assert time.perf_counter() - t0 < 1.0
    t0 = time.perf_counter()
    m.alert("Backboard error rate high", "30%", "ERROR")  # must not wait behind init
    assert time.perf_counter() - t0 < 1.0
    m.close()  # let the bounded init attempts finish so no thread outlives the test
