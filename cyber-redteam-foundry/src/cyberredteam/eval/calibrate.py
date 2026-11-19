"""Judge calibration harness (WP5).

Runs the judge over the labelled, benign transcripts in ``eval/datasets/`` and
reports precision, recall and Cohen's kappa against the labels (positive class
= ``unsafe``), as JSON plus Markdown.

Two sections:

* ``judge`` (primary, gated by ``--compare``): the judge alone. It sees **no**
  deterministic hits, and the verdict rules apply without them (k votes, valid
  vote count, agreement threshold, consensus table). Predicted unsafe =
  ``confirmed``/``unconfirmed``. Measuring the judge without the monitors means
  a judge or prompt regression cannot hide behind the deterministic override.
* ``pipeline``: the same votes with the WP5 canary and forbidden-tool monitors
  applied, i.e. the end-to-end verdict.

An ``inconclusive`` prediction counts as "not unsafe" (a miss on an unsafe
item, which lowers recall); its rate is reported separately.

``--compare baseline.json`` exits 1 if precision or recall of either section
drops by more than ``--tolerance`` (default 0.02 = 2 points). The baseline is
the ``calibration_report.json`` of an accepted earlier run (no baseline is
committed until a real Backboard run exists). CI (WP10) runs::

    uv run python -m cyberredteam.eval.calibrate --out-dir runs/calibration \\
        --compare <accepted calibration_report.json>

A real run needs Backboard (role ``judge`` in ``configs/models.yaml``). Tests
inject a fake judge through ``main(argv, judge=...)``.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cyberredteam.contracts import Conversation
from cyberredteam.engine.types import MonitorContext
from cyberredteam.eval.dataset import DEFAULT_FILES, LabelledTranscript, load_dataset
from cyberredteam.evaluation.judge import Judge
from cyberredteam.evaluation.pipeline import asi_class_for
from cyberredteam.evaluation.technique_specs import get_spec
from cyberredteam.evaluation.verdict import EvaluationSettings, JudgeOutcome, decide_verdict
from cyberredteam.monitors import CanaryMonitor, ForbiddenToolMonitor

SECTIONS = ("judge", "pipeline")
METRICS = ("precision", "recall")
DEFAULT_TOLERANCE = 0.02
_PLACEHOLDER_TARGET = {
    "target_id": "00000000-0000-4000-8000-000000000000",
    "name": "calibration",
    "endpoint": "http://fake-target.test/chat",
    "session_mode": "stateless_history",
    "environment": "staging",
}


# ── Metrics ──────────────────────────────────────────────────────────────────


@dataclass
class Confusion:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    inconclusive: int = 0

    def add(self, label: str, predicted_unsafe: bool, inconclusive: bool) -> None:
        if inconclusive:
            self.inconclusive += 1
        if label == "unsafe":
            if predicted_unsafe:
                self.tp += 1
            else:
                self.fn += 1
        elif predicted_unsafe:
            self.fp += 1
        else:
            self.tn += 1

    @property
    def n(self) -> int:
        return self.tp + self.fp + self.tn + self.fn


def metrics(c: Confusion) -> dict[str, Any]:
    n = c.n
    precision = c.tp / (c.tp + c.fp) if c.tp + c.fp else 0.0
    recall = c.tp / (c.tp + c.fn) if c.tp + c.fn else 0.0
    if n:
        po = (c.tp + c.tn) / n
        pe = ((c.tp + c.fp) * (c.tp + c.fn) + (c.fn + c.tn) * (c.fp + c.tn)) / (n * n)
        kappa = (po - pe) / (1 - pe) if pe < 1 else (1.0 if po == 1 else 0.0)
    else:
        kappa = 0.0
    return {
        "n": n,
        "tp": c.tp,
        "fp": c.fp,
        "tn": c.tn,
        "fn": c.fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "kappa": round(kappa, 4),
        "inconclusive": c.inconclusive,
        "inconclusive_rate": round(c.inconclusive / n, 4) if n else 0.0,
    }


# ── Running ──────────────────────────────────────────────────────────────────


async def _with_monitor_hits(item: LabelledTranscript) -> Conversation:
    from cyberredteam.contracts import TargetConfig

    ctx = MonitorContext(
        campaign_id="calibration",
        conversation_id=item.conversation.conversation_id,
        technique=item.conversation.technique,
        target=TargetConfig.model_validate(_PLACEHOLDER_TARGET),
        canary_values=tuple(item.canary_values),
        forbidden_tools=frozenset(item.forbidden_tools),
    )
    monitors = [CanaryMonitor(), ForbiddenToolMonitor()]
    turns = []
    for t in item.conversation.turns:
        names: list[str] = []
        for m in monitors:
            res = await m.check(t, ctx)
            names += [h.name for h in res.hits]
        turns.append(t.model_copy(update={"monitor_hits": names}))
    return item.conversation.model_copy(update={"turns": turns})


async def _evaluate_item(item: LabelledTranscript, judge: Judge, settings: EvaluationSettings) -> dict[str, Any]:
    blind = item.conversation.model_copy(
        update={"turns": [t.model_copy(update={"monitor_hits": []}) for t in item.conversation.turns]}
    )
    asi = asi_class_for(blind.technique)
    outcome: JudgeOutcome = await judge.judge(blind, technique_spec=get_spec(asi), deterministic_hits=[])
    judge_verdict = decide_verdict(blind, outcome, asi_class=asi, settings=settings)
    pipeline_verdict = decide_verdict(await _with_monitor_hits(item), outcome, asi_class=asi, settings=settings)
    return {
        "id": item.item_id,
        "label": item.label,
        "source": item.source,
        "judge": judge_verdict.verdict,
        "pipeline": pipeline_verdict.verdict,
        "agreement": judge_verdict.judge_agreement,
        "valid_votes": outcome.valid_count,
    }


async def run_calibration(
    items: list[LabelledTranscript],
    judge: Judge,
    settings: EvaluationSettings | None = None,
    concurrency: int = 4,
) -> dict[str, Any]:
    settings = settings or EvaluationSettings()
    sem = asyncio.Semaphore(max(1, concurrency))

    async def one(item: LabelledTranscript) -> dict[str, Any]:
        async with sem:
            return await _evaluate_item(item, judge, settings)

    rows = await asyncio.gather(*[one(i) for i in items])
    report: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "judge_model": judge.model_name,
        "k": judge.k,
        "agreement_threshold": settings.agreement_threshold,
        "items": len(items),
        "labels": {
            "unsafe": sum(1 for i in items if i.label == "unsafe"),
            "safe": sum(1 for i in items if i.label == "safe"),
        },
    }
    for section in SECTIONS:
        c = Confusion()
        for r in rows:
            v = r[section]
            c.add(r["label"], v in ("confirmed", "unconfirmed"), v == "inconclusive")
        report[section] = metrics(c)
    report["errors"] = [
        {"id": r["id"], "label": r["label"], "judge": r["judge"], "pipeline": r["pipeline"]}
        for r in rows
        if (r["judge"] in ("confirmed", "unconfirmed")) != (r["label"] == "unsafe")
    ]
    return report


# ── Reporting and comparison ─────────────────────────────────────────────────


def to_markdown(report: dict[str, Any], regressions: list[str] | None = None) -> str:
    lines = [
        "# Judge calibration report",
        "",
        f"- generated: {report.get('generated_at', '')}",
        f"- judge model: {report.get('judge_model')}, k={report.get('k')}, "
        f"agreement threshold={report.get('agreement_threshold')}",
        f"- items: {report.get('items')} (unsafe {report['labels']['unsafe']}, safe {report['labels']['safe']})",
        "",
        "| section | precision | recall | kappa | tp | fp | tn | fn | inconclusive |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for s in SECTIONS:
        m = report[s]
        lines.append(
            f"| {s} | {m['precision']:.4f} | {m['recall']:.4f} | {m['kappa']:.4f} | {m['tp']} | "
            f"{m['fp']} | {m['tn']} | {m['fn']} | {m['inconclusive']} ({m['inconclusive_rate']:.1%}) |"
        )
    lines += ["", "`judge` = judge alone (no deterministic hits); `pipeline` = with WP5 monitors."]
    if regressions is not None:
        lines += ["", "## Baseline comparison", ""]
        lines += [f"- REGRESSION: {r}" for r in regressions] or ["- no regression beyond tolerance"]
    if report.get("errors"):
        lines += ["", "## Judge errors", ""]
        lines += [f"- {e['id']} label={e['label']} judge={e['judge']}" for e in report["errors"][:50]]
    return "\n".join(lines) + "\n"


def compare(report: dict[str, Any], baseline: dict[str, Any], tolerance: float = DEFAULT_TOLERANCE) -> list[str]:
    """Regressions where precision or recall fell by more than ``tolerance``."""
    out: list[str] = []
    for section in SECTIONS:
        if section not in baseline:
            continue
        for metric in METRICS:
            old, new = float(baseline[section][metric]), float(report[section][metric])
            if old - new > tolerance + 1e-9:
                out.append(f"{section}.{metric} dropped {old:.4f} -> {new:.4f} (> {tolerance:.2f})")
    return out


def main(argv: list[str] | None = None, *, judge: Judge | None = None) -> int:
    parser = argparse.ArgumentParser(description="Calibrate the WP5 judge against labelled transcripts.")
    parser.add_argument("--dataset", action="append", help="JSONL file (repeatable); default: packaged sets")
    parser.add_argument("--out-dir", default="runs/calibration")
    parser.add_argument("--compare", help="baseline report JSON; exit 1 on a regression")
    parser.add_argument("--tolerance", type=float, default=DEFAULT_TOLERANCE)
    parser.add_argument("--k", type=int, default=None, help="judge votes (default CANARY_JUDGE_VOTES or 3)")
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args(argv)

    settings = EvaluationSettings.from_env()
    k = args.k or settings.judge_votes
    items = load_dataset(tuple(args.dataset) if args.dataset else DEFAULT_FILES)
    if args.limit:
        items = items[: args.limit]
    judge = judge or Judge(k=k)
    report = asyncio.run(run_calibration(items, judge, settings, args.concurrency))

    regressions: list[str] | None = None
    if args.compare:
        baseline = json.loads(Path(args.compare).read_text(encoding="utf-8"))
        regressions = compare(report, baseline, args.tolerance)
        report["comparison"] = {"baseline": args.compare, "regressions": regressions}

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "calibration_report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (out / "calibration_report.md").write_text(to_markdown(report, regressions), encoding="utf-8")
    j = report["judge"]
    print(f"judge precision={j['precision']:.4f} recall={j['recall']:.4f} kappa={j['kappa']:.4f} -> {out}")
    if regressions:
        for r in regressions:
            print(f"REGRESSION: {r}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
