"""Review-fix tests: fail-closed comparison, CLI error handling, demo hygiene, bundle scan."""

import os
import subprocess
import tempfile
from pathlib import Path

import pytest
from pydantic import ValidationError
from storage_v2_support import make_policy, make_target  # noqa: F401
from typer.testing import CliRunner

from cyberredteam.cli import app
from cyberredteam.contracts import TechniqueResult
from cyberredteam.gate import GatePolicy, GateStatus, TechniqueOverride, compare
from cyberredteam.gate.report import to_markdown

runner = CliRunner()
PATTERNS = Path(__file__).resolve().parents[2] / ".github" / "bundle-secret-patterns.txt"


def tr(name, trials, confirmed):
    return TechniqueResult.from_counts(name, trials, confirmed)


def test_skipped_plus_new_is_not_a_pass():
    p = GatePolicy(overrides={"a": TechniqueOverride(skip=True)})
    r = compare([tr("a", 20, 1)], [tr("a", 20, 1), tr("b", 20, 1)], p)
    assert r.status is GateStatus.INCONCLUSIVE
    assert any("skipped by policy: a" in w for w in r.warnings)


def test_disjoint_techniques_with_missing_ignored_is_not_a_pass():
    r = compare([tr("a", 20, 1)], [tr("b", 20, 1)], GatePolicy(missing_technique="ignore"))
    assert r.status is GateStatus.INCONCLUSIVE


def test_duplicate_techniques_fail_closed():
    # last-wins would hide the regression in the first entry
    r = compare([tr("a", 20, 0)], [tr("a", 20, 12), tr("a", 20, 0)])
    assert r.status is GateStatus.INCONCLUSIVE
    assert any("duplicate technique in candidate: a" in w for w in r.warnings)
    r = compare([tr("a", 20, 0), tr("a", 20, 0)], [tr("a", 20, 12)])
    assert r.status is GateStatus.INCONCLUSIVE


def test_policy_min_trials_floor():
    with pytest.raises(ValidationError):
        GatePolicy(min_trials=2)
    with pytest.raises(ValidationError):
        TechniqueOverride(min_trials=1)


def test_skipped_technique_visible_in_report():
    r = compare([tr("a", 20, 1), tr("b", 20, 1)], [tr("a", 20, 1), tr("b", 20, 1)],
                GatePolicy(overrides={"b": TechniqueOverride(skip=True)}))
    md = to_markdown(r, target="t", suite="s", baseline="b", candidate="c")
    assert "| b | skipped" in md and "technique skipped by policy: b" in md


def test_output_write_error_exits_2_not_1(tmp_path):
    bad = tmp_path / "missing-dir" / "r.json"
    r = runner.invoke(app, ["gate", "--demo", "--demo-inject-regression", "--json-out", str(bad)])
    assert r.exit_code == 2


@pytest.mark.parametrize(
    "extra", [["--candidate", "x"], ["--target", "t"], ["--baseline", "b"], ["--db-url", "sqlite://"]]
)
def test_demo_rejects_other_selectors(extra):
    assert runner.invoke(app, ["gate", "--demo", *extra]).exit_code == 2


def test_demo_restores_env_and_cleans_tempdir(monkeypatch):
    monkeypatch.delenv("CANARY_ENCRYPTION_KEY", raising=False)
    before = set(Path(tempfile.gettempdir()).glob("canary-gate-*"))
    assert runner.invoke(app, ["gate", "--demo"]).exit_code == 0
    assert "CANARY_ENCRYPTION_KEY" not in os.environ
    assert set(Path(tempfile.gettempdir()).glob("canary-gate-*")) == before


CLEAN = (
    'const a="task-list-item-checkbox-container-wrapper";className:"sk-loading-spinner-x"'
    ',b="flex items-center gap-2 px-4 py-2 text-sm bg-slate-900 disk-usage-indicator-bar-long";'
    "headers:{Authorization:`Bearer ${token}`}"
)
LEAKS = {
    "anthropic": 'x="sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789";',
    "openai": 'k:"sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"',
    "aws": 'id:"AKIA' 'ABCDEFGHIJKLMNOP"',
    "github": 't="ghp_' + "a" * 36 + '"',
    "pem": 's="-----BEGIN RSA' ' PRIVATE KEY-----MIIE"',
    "jwt": 'h="Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"',
}


def scan(tmp_path, text):
    f = tmp_path / "dist" / "index.js"
    f.parent.mkdir(exist_ok=True)
    f.write_text(text)
    r = subprocess.run(
        ["grep", "-rlEf", str(PATTERNS), str(tmp_path / "dist")], capture_output=True, text=True
    )
    return r.returncode == 0, r.stdout


def test_bundle_scan_no_false_positive_on_tailwind_like_bundle(tmp_path):
    assert scan(tmp_path, CLEAN) == (False, "")


@pytest.mark.parametrize("name", sorted(LEAKS))
def test_bundle_scan_detects_real_secret_shapes(tmp_path, name):
    hit, out = scan(tmp_path, CLEAN + LEAKS[name])
    assert hit
    assert "sk-" not in out and "AKIA" not in out  # filenames only, never the match
