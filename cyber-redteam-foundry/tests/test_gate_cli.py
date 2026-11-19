import json
from pathlib import Path

import pytest
import yaml
from cryptography.fernet import Fernet
from storage_v2_support import make_policy, make_target
from typer.testing import CliRunner

from cyberredteam.cli import app
from cyberredteam.contracts import TechniqueResult
from cyberredteam.storage.v2 import orm
from cyberredteam.storage.v2.db import make_engine, make_session_factory
from cyberredteam.storage.v2.encrypted import reset_key_cache
from cyberredteam.storage.v2.repositories import CampaignRepo, SqlTargetStore

runner = CliRunner()
ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def _key(monkeypatch):
    monkeypatch.setenv("CANARY_ENCRYPTION_KEY", Fernet.generate_key().decode())
    reset_key_cache()
    yield
    reset_key_cache()


@pytest.fixture
def seeded(tmp_path):
    url = f"sqlite:///{tmp_path / 'g.db'}"
    engine = make_engine(url)
    orm.Base.metadata.create_all(engine)
    f = make_session_factory(engine)
    target = make_target()
    SqlTargetStore(f).create(target)
    repo = CampaignRepo(f)

    def add(cid, rows):
        repo.create(cid, target.target_id, make_policy())
        repo.save_technique_results(cid, [TechniqueResult.from_counts(*r) for r in rows])

    add("base", [("a", 20, 0)])
    add("same", [("a", 20, 1)])
    add("bad", [("a", 20, 12)])
    add("thin", [("a", 2, 2)])
    repo.create("empty", target.target_id, make_policy())
    return url, target.target_id


def gate(url, tid, cand, *extra):
    return runner.invoke(
        app,
        ["gate", "--target", tid, "--baseline", "base", "--candidate", cand,
         "--db-url", url, *extra],
    )


@pytest.mark.parametrize(
    "cand,code", [("same", 0), ("bad", 1), ("thin", 2), ("empty", 2), ("nope", 2)]
)
def test_exit_codes(seeded, cand, code):
    url, tid = seeded
    assert gate(url, tid, cand).exit_code == code


def test_wrong_target_is_error(seeded):
    url, _ = seeded
    assert gate(url, "other-target", "same").exit_code == 2


def test_missing_candidate_without_launcher_is_error(seeded):
    url, tid = seeded
    r = runner.invoke(app, ["gate", "--target", tid, "--baseline", "base", "--db-url", url])
    assert r.exit_code == 2


def test_summary_and_json_outputs(seeded, tmp_path, monkeypatch):
    url, tid = seeded
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    out = tmp_path / "r.json"
    r = gate(url, tid, "bad", "--json-out", str(out))
    assert r.exit_code == 1
    assert "REGRESSION" in summary.read_text()
    assert json.loads(out.read_text())["exit_code"] == 1


def test_demo_passes():
    assert runner.invoke(app, ["gate", "--demo"]).exit_code == 0


def test_demo_injected_regression_fails():
    r = runner.invoke(app, ["gate", "--demo", "--demo-inject-regression"])
    assert r.exit_code == 1


def test_workflow_yaml_valid_and_minimal_permissions():
    wf = yaml.safe_load((ROOT / ".github" / "workflows" / "canary-gate.yml").read_text())
    assert wf["permissions"] == {"contents": "read"}
    triggers = wf.get("on", wf.get(True))
    assert "pull_request" in triggers and "workflow_dispatch" in triggers
    assert {"backend", "gate", "frontend"} <= set(wf["jobs"])
