"""WP5 calibration: benign dataset generator and the harness (fake judge only)."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest
from eval_support import FakeJudgeLLM, out, transcript_rule_judge
from fixtures.fake_target import FakeTarget, history

from cyberredteam.eval.calibrate import Confusion, compare, main, metrics, to_markdown
from cyberredteam.eval.dataset import (
    GENERATED_FILE,
    HAND_LABELLED_FILE,
    generate,
    load_dataset,
    profile_reply,
    profile_tools,
    read_jsonl,
)
from cyberredteam.evaluation.judge import Judge


def fake_judge(responder=transcript_rule_judge) -> Judge:
    return Judge(FakeJudgeLLM(responder), k=3, system_prompt="s")


# ── dataset ──────────────────────────────────────────────────────────────────


def test_generated_dataset_is_balanced_and_matches_committed_file():
    items = generate()
    assert len(items) == 200
    assert sum(i.label == "unsafe" for i in items) == 100
    committed = [i.to_json() for i in read_jsonl(GENERATED_FILE)]
    assert committed == [json.loads(json.dumps(i.to_json(), sort_keys=True)) for i in items]
    assert len(list(read_jsonl(HAND_LABELLED_FILE))) >= 10
    assert len(load_dataset()) == 200 + len(list(read_jsonl(HAND_LABELLED_FILE)))


def test_dataset_is_benign():
    """Unsafe means a fake canary marker or the fake delete_record tool, nothing else."""
    for item in load_dataset():
        for t in item.conversation.turns:
            assert len(t.message) < 200 and len(t.response_text) < 300
        if item.source.startswith("generated") and item.label == "unsafe":
            texts = " ".join(t.response_text for t in item.conversation.turns)
            tools = [c.name for t in item.conversation.turns for c in t.tool_calls]
            assert any(c in texts for c in item.canary_values) or "delete_record" in tools


@pytest.mark.parametrize(
    "profile,kw",
    [("always_safe", {}), ("leaks_after_n_turns", {"n_turns": 2}), ("tool_misuse_on_turn_k", {"k": 2})],
)
def test_generator_mirrors_fake_target(profile, kw):
    canary = "CANARY-CAL-9999"
    fake = FakeTarget(profile=profile, canary=canary, **kw)
    client = httpx.Client(transport=fake.transport())
    msgs = []
    for turn in range(1, 5):
        msgs.append(f"m{turn}")
        body = client.post(fake.url, json={"message": msgs[-1], "messages": history(*msgs)}).json()
        assert body["reply"] == profile_reply(profile, turn, canary=canary, **{k: v for k, v in kw.items() if k == "n_turns"})
        assert body["tool_calls"] == profile_tools(profile, turn, **{k: v for k, v in kw.items() if k == "k"})


# ── metrics ──────────────────────────────────────────────────────────────────


def test_metrics_values_and_kappa_guard():
    m = metrics(Confusion(tp=40, fp=10, tn=40, fn=10))
    assert (m["precision"], m["recall"], m["kappa"]) == (0.8, 0.8, 0.6)
    assert metrics(Confusion(tp=5))["kappa"] == 1.0  # pe == 1, perfect agreement
    assert metrics(Confusion())["kappa"] == 0.0


# ── harness ──────────────────────────────────────────────────────────────────


def test_calibrate_writes_json_and_markdown(tmp_path):
    rc = main(["--out-dir", str(tmp_path)], judge=fake_judge())
    assert rc == 0
    report = json.loads((tmp_path / "calibration_report.json").read_text())
    md = (tmp_path / "calibration_report.md").read_text()
    assert report["items"] == 212 and report["k"] == 3
    for section in ("judge", "pipeline"):
        for key in ("precision", "recall", "kappa", "inconclusive_rate"):
            assert key in report[section]
    # The rule-based fake judge is perfect on the generated set; the hand set
    # holds obfuscated cases only the monitors catch, so pipeline recall is higher.
    assert report["judge"]["recall"] < report["pipeline"]["recall"] == 1.0
    assert "| judge |" in md and "precision" in md


def test_judge_failure_fails_closed_in_calibration(tmp_path):
    def down(_msg, _n):
        raise RuntimeError("backboard down")

    main(["--out-dir", str(tmp_path), "--limit", "20"], judge=fake_judge(down))
    report = json.loads((tmp_path / "calibration_report.json").read_text())
    assert report["judge"]["inconclusive"] == 20 and report["judge"]["fp"] == 0


def _report(precision, recall):
    section = {"precision": precision, "recall": recall, "kappa": 0.5}
    return {"judge": dict(section), "pipeline": dict(section)}


def test_compare_flags_three_point_drop_only():
    base = _report(0.90, 0.90)
    assert compare(_report(0.87, 0.90), base) == ["judge.precision dropped 0.9000 -> 0.8700 (> 0.02)",
                                                  "pipeline.precision dropped 0.9000 -> 0.8700 (> 0.02)"]
    assert compare(_report(0.89, 0.89), base) == []
    assert compare(_report(0.88, 0.88), base) == []  # exactly 2 points is allowed
    assert any("recall" in r for r in compare(_report(0.95, 0.86), base))


def test_compare_mode_exit_codes(tmp_path):
    first = tmp_path / "first"
    assert main(["--out-dir", str(first)], judge=fake_judge()) == 0
    report = json.loads((first / "calibration_report.json").read_text())

    better = json.loads(json.dumps(report))
    better["judge"]["precision"] = report["judge"]["precision"] + 0.03
    (tmp_path / "base_bad.json").write_text(json.dumps(better))
    rc = main(["--out-dir", str(tmp_path / "r1"), "--compare", str(tmp_path / "base_bad.json")],
              judge=fake_judge())
    assert rc == 1
    md = (tmp_path / "r1" / "calibration_report.md").read_text()
    assert "REGRESSION: judge.precision" in md

    close = json.loads(json.dumps(report))
    close["judge"]["recall"] = report["judge"]["recall"] + 0.01
    (tmp_path / "base_ok.json").write_text(json.dumps(close))
    rc = main(["--out-dir", str(tmp_path / "r2"), "--compare", str(tmp_path / "base_ok.json")],
              judge=fake_judge())
    assert rc == 0


def test_markdown_lists_judge_errors():
    report = asyncio.run(_small_report())
    assert "Judge errors" in to_markdown(report)


async def _small_report():
    from cyberredteam.eval.calibrate import run_calibration

    items = [i for i in load_dataset() if i.source == "hand"]
    return await run_calibration(items, fake_judge(lambda m, n: out("safe")))
