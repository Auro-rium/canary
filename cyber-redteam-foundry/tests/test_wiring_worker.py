"""Worker start wiring: init_observability (no-op without a key), providers,
register_target_secrets, runner defaults (WP5 monitors replace the builtin one)."""

from __future__ import annotations

import asyncio

import pytest
from jobs_support import seed_campaign
from storage_v2_support import make_target

from cyberredteam.jobs import worker as worker_mod
from cyberredteam.jobs.control import ControlStore
from cyberredteam.observability import setup


@pytest.fixture
def fresh_observability(monkeypatch):
    monkeypatch.setattr(setup, "_handle", None)
    yield
    monkeypatch.setattr(setup, "_handle", None)


def test_worker_main_initialises_observability_with_the_three_providers(monkeypatch):
    calls = {}

    class FakeApp:
        def run_worker(self, **kw):
            calls["ran"] = kw

    class FakeRuntime:
        factory = object()

    monkeypatch.setattr(worker_mod, "make_connector", lambda url: object())
    monkeypatch.setattr(worker_mod, "build_runtime", lambda *a, **k: FakeRuntime())
    monkeypatch.setattr(worker_mod, "make_app", lambda connector, runtime: FakeApp())
    monkeypatch.setattr(worker_mod, "observability_providers", lambda f: {"queue_depth": 1, "active_campaigns": 2, "kill_switch": 3})

    def fake_init(settings, service_name="api", providers=None, ops_webhook_url=None):
        calls["init"] = (service_name, providers)

    monkeypatch.setattr(worker_mod, "init_observability", fake_init)
    worker_mod.main()
    assert calls["init"] == ("worker", {"queue_depth": 1, "active_campaigns": 2, "kill_switch": 3})
    assert "ran" in calls


def test_init_observability_is_a_noop_without_a_wandb_key(monkeypatch, fresh_observability):
    monkeypatch.delenv("WANDB_API_KEY", raising=False)
    monkeypatch.setenv("WANDB_MODE", "online")
    from cyberredteam.observability import hooks
    from cyberredteam.observability.hooks import NoopMetrics
    from cyberredteam.settings import get_settings

    monkeypatch.setattr(hooks, "_metrics", NoopMetrics(), raising=False)
    handle = setup.init_observability(get_settings(), service_name="worker", providers={})
    assert handle.enabled is False and handle.active is False
    hooks.get_metrics().campaign_finished("c", {"status": "completed"})  # does not raise


def test_providers_report_active_campaigns_and_kill_switch(db_factory):
    providers = worker_mod.observability_providers(db_factory)
    assert providers["active_campaigns"]() == 0.0 and providers["kill_switch"]() == 0.0
    seed_campaign(db_factory, status="running")
    seed_campaign(db_factory, status="completed")
    assert providers["active_campaigns"]() == 1.0
    ControlStore(db_factory).set_kill_switch(True, "test")
    assert providers["kill_switch"]() == 1.0


def test_runner_registers_target_secrets_and_uses_the_wp5_monitors(db_factory, monkeypatch):
    from storage_v2_support import make_policy

    from cyberredteam.contracts import CampaignRequest
    from cyberredteam.engine import BuiltinSafetyMonitor
    from cyberredteam.jobs.control import DbRunControl
    from cyberredteam.jobs.execution import JobRuntime
    from cyberredteam.jobs.runner_wiring import make_runner
    from cyberredteam.monitors import CanaryMonitor, ForbiddenToolMonitor

    captured = {}

    async def fake_run_campaign(request, campaign_id, deps):
        captured["deps"] = deps

    monkeypatch.setattr("cyberredteam.jobs.runner_wiring.run_campaign", fake_run_campaign)
    registered = []
    monkeypatch.setattr("cyberredteam.jobs.runner_wiring.register_target_secrets", registered.append)
    rt = JobRuntime(factory=db_factory, runner=None, control=DbRunControl(db_factory))
    runner = make_runner(rt, planner_factory=lambda spec: None)
    target = make_target()
    asyncio.run(runner(CampaignRequest(target=target, policy=make_policy()), "c1"))
    deps = captured["deps"]
    kinds = [type(m) for m in deps.monitors]
    assert CanaryMonitor in kinds and ForbiddenToolMonitor in kinds
    assert BuiltinSafetyMonitor not in kinds  # never stacked: same hit names
    assert registered == [target]
    assert deps.evaluator is not None and deps.aggregate_results is not None


def test_safety_config_per_target_then_default_then_empty_and_invalid_fails(tmp_path):
    from cyberredteam.jobs.evaluation_wiring import safety_config_for

    target = make_target()
    assert safety_config_for(target, None).canary_values == ()
    assert safety_config_for(target, tmp_path).canary_values == ()  # directory without files
    (tmp_path / "default.yaml").write_text("canary_values: ['default-canary-1']\n", encoding="utf-8")
    assert safety_config_for(target, tmp_path).canary_values == ("default-canary-1",)
    (tmp_path / f"{target.target_id}.yaml").write_text(
        "canary_values: ['target-canary-1']\nforbidden_tools: ['drop_table']\n", encoding="utf-8")
    cfg = safety_config_for(target, tmp_path)
    assert cfg.canary_values == ("target-canary-1",) and cfg.forbidden_tools == {"drop_table"}
    (tmp_path / f"{target.target_id}.yaml").write_text("canary_values: ['short']\n", encoding="utf-8")
    with pytest.raises(ValueError):  # an invalid file fails the campaign, never runs without canaries
        safety_config_for(target, tmp_path)


def test_dockerfile_copies_packs_but_never_the_planner_prompt():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    docker = (root / "Dockerfile").read_text()
    assert "COPY packs ./packs" in docker
    copies = [ln for ln in docker.splitlines() if ln.startswith(("COPY", "ADD"))]
    assert not any("planner" in ln for ln in copies)  # the file is mounted at runtime, never baked in
    ignore = (root / ".dockerignore").read_text().splitlines()
    assert "prompts/planner.md" in ignore
    assert not (root / "prompts" / "planner.md").exists()
