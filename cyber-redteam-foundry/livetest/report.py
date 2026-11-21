"""Run report (Markdown + JSON). Never contains secret values: names only."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Check:
    name: str
    status: str  # pass | fail | skip
    detail: str = ""


@dataclass
class StepResult:
    step: int
    title: str
    status: str = "pass"  # pass | fail | skip | aborted | error
    checks: list[Check] = field(default_factory=list)
    seconds: float = 0.0
    spend_usd: float = 0.0
    error: str = ""
    notes: list[str] = field(default_factory=list)

    def finalize(self) -> None:
        if self.status in {"aborted", "error"}:
            return
        ran = [c for c in self.checks if c.status != "skip"]
        if any(c.status == "fail" for c in self.checks):
            self.status = "fail"
        elif not ran:
            self.status = "skip"
        else:
            self.status = "pass"


@dataclass
class RunReport:
    run_id: str
    mode: str
    started: float = field(default_factory=time.time)
    preflight: dict[str, Any] = field(default_factory=dict)
    capabilities: dict[str, bool] = field(default_factory=dict)
    models: dict[str, Any] = field(default_factory=dict)
    steps: list[StepResult] = field(default_factory=list)
    spend: dict[str, Any] = field(default_factory=dict)
    teardown: list[str] = field(default_factory=list)
    timings: dict[str, float] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def overall(self) -> str:
        if any(s.status in {"fail", "error"} for s in self.steps):
            return "FAIL"
        if any(s.status == "aborted" for s in self.steps):
            return "ABORTED"
        if self.teardown:
            return "FAIL"
        return "PASS"

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "mode": self.mode,
            "overall": self.overall(),
            "preflight": self.preflight,
            "capabilities": self.capabilities,
            "models": self.models,
            "spend": self.spend,
            "timings_s": self.timings,
            "teardown_problems": self.teardown,
            "notes": self.notes,
            "steps": [
                {
                    "step": s.step, "title": s.title, "status": s.status, "seconds": round(s.seconds, 2),
                    "spend_usd": round(s.spend_usd, 6), "error": s.error, "notes": s.notes,
                    "checks": [{"name": c.name, "status": c.status, "detail": c.detail} for c in s.checks],
                }
                for s in self.steps
            ],
        }

    def to_markdown(self) -> str:
        d = self.to_dict()
        lines = [f"# Live test A report ({self.mode})", "", f"- run id: `{self.run_id}`", f"- overall: **{d['overall']}**"]
        sp = self.spend
        if sp:
            lines.append(
                f"- spend: charged ${sp.get('charged_usd', 0):.4f} of ${sp.get('budget_usd', 0):.2f} budget "
                f"(hard cap ${sp.get('hard_cap_usd', 5):.2f}); estimated at real rates "
                f"${sp.get('estimated_at_real_rates_usd', 0):.4f}"
            )
        lines += ["", "## Models", "", "```json", json.dumps(self.models, indent=2), "```", "", "## Capabilities", ""]
        for k, v in self.capabilities.items():
            lines.append(f"- {k}: {'yes' if v else 'NO'}")
        lines += ["", "## Preflight", "", "```json", json.dumps(self.preflight, indent=2), "```", "", "## Steps", "",
                  "| # | step | result | seconds | spend USD |", "|---|---|---|---|---|"]
        for s in d["steps"]:
            lines.append(f"| {s['step']} | {s['title']} | {s['status'].upper()} | {s['seconds']} | {s['spend_usd']:.4f} |")
        for s in d["steps"]:
            lines += ["", f"### Step {s['step']}: {s['title']} ({s['status'].upper()})", ""]
            if s["error"]:
                lines.append(f"error: {s['error']}")
            for n in s["notes"]:
                lines.append(f"- note: {n}")
            for c in s["checks"]:
                lines.append(f"- [{c['status'].upper()}] {c['name']}" + (f": {c['detail']}" if c["detail"] else ""))
        lines += ["", "## Spend per step", "", "```json", json.dumps(sp, indent=2), "```", "",
                  "## Teardown", "", "clean" if not self.teardown else "problems: " + ", ".join(self.teardown), ""]
        if self.notes:
            lines += ["## Notes", ""] + [f"- {n}" for n in self.notes] + [""]
        return "\n".join(lines)

    def write(self, directory: Path, forbidden: list[str]) -> tuple[Path, Path]:
        """Write report.md/report.json; refuses (raises) if a secret value would be written."""
        md, js = self.to_markdown(), json.dumps(self.to_dict(), indent=2)
        for v in forbidden:
            if v and (v in md or v in js):
                raise RuntimeError("refusing to write a report containing a secret value")
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "report.md").write_text(md, encoding="utf-8")
        (directory / "report.json").write_text(js, encoding="utf-8")
        return directory / "report.md", directory / "report.json"
