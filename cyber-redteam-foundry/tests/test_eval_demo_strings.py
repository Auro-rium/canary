"""B1: demo-target strings live in configs/demo_target.yaml, never in src/."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
DEMO_STRINGS = re.compile(r"pr0d_s3cr3t|sk-internal|david park|bob martinez|employee_lookup", re.I)


def test_no_demo_strings_in_src():
    offenders = [
        str(p.relative_to(ROOT))
        for p in (ROOT / "src").rglob("*")
        if p.is_file() and p.suffix in {".py", ".md", ".yaml", ".yml", ".json", ".txt"}
        and DEMO_STRINGS.search(p.read_text(encoding="utf-8", errors="ignore"))
    ]
    assert offenders == []


def test_demo_strings_moved_to_demo_target_config():
    cfg = yaml.safe_load((ROOT / "configs" / "demo_target.yaml").read_text())
    joined = " ".join(cfg["canary_values"] + cfg["forbidden_tools"])
    for s in ("pr0d_s3cr3t", "sk-internal", "David Park", "Bob Martinez", "employee_lookup"):
        assert s in joined
    assert all(len(c) >= 8 for c in cfg["canary_values"])
