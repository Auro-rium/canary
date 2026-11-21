"""Spend guard for the Live test A harness: the cap can never be crossed."""

from __future__ import annotations

import pytest

from livetest.secrets_loader import Secrets
from livetest.spend import HARD_CAP_USD, BudgetAbort, Rates, SpendGuard


def guard(**kw) -> SpendGuard:
    return SpendGuard(rates=Rates(0.003, 0.015), judge_prompt_tokens=1500, **kw)


def test_budget_cannot_exceed_hard_cap():
    with pytest.raises(ValueError):
        guard(budget_usd=HARD_CAP_USD + 0.01)
    with pytest.raises(ValueError):
        guard(budget_usd=0)


def test_reserve_aborts_before_crossing_budget():
    g = guard(budget_usd=1.0)
    est = g.conversations_usd(5, 4)
    g.reserve_check("a", est)
    g.charge("a", est, "judge_estimate")
    big = g.conversations_usd(100, 4)
    with pytest.raises(BudgetAbort):
        g.reserve_check("b", big)
    assert g.spent_usd == pytest.approx(est)


def test_held_reservations_count_before_settlement():
    g = guard(budget_usd=1.2)
    est = g.conversations_usd(5, 4)  # ~0.50
    g.reserve_check("a", est)
    g.hold("a", est)
    g.reserve_check("a", est)  # ~1.0 <= 1.2
    g.hold("a", est)
    with pytest.raises(BudgetAbort):
        g.reserve_check("a", est)  # ~1.5 > 1.2
    g.release("a")
    g.reserve_check("a", est)


def test_total_across_steps_never_exceeds_cap():
    g = guard(budget_usd=4.5)
    total = 0.0
    for i in range(1000):
        est = g.conversations_usd(5, 4)
        try:
            g.reserve_check(f"s{i}", est)
        except BudgetAbort:
            break
        g.charge(f"s{i}", est, "judge_estimate")
        total += est
        assert g.spent_usd <= HARD_CAP_USD
    assert g.spent_usd <= 4.5


def test_dry_run_charges_nothing_but_tracks_would_spend():
    g = guard(budget_usd=0.5, dry_run=True)
    est = g.conversations_usd(5, 4)
    g.charge("a", est, "judge_estimate")
    assert g.spent_usd == 0
    assert g.would_spend_usd == pytest.approx(est)
    with pytest.raises(BudgetAbort):  # the guard logic is still exercised in dry-run
        g.reserve_check("b", est)


def test_would_kinds_never_count_in_a_real_run():
    g = guard(budget_usd=4.5)
    g.charge("a", 3.0, "would_judge_if_wired")
    assert g.spent_usd == 0
    assert g.step_total("a") == 0


def test_campaign_cap_bounded_and_positive():
    g = guard(budget_usd=4.5)
    assert 0.01 <= g.campaign_cap_usd(0.1) <= 0.5
    g.spent_usd = 4.49
    assert g.campaign_cap_usd(0.0) == 0.01


def test_secrets_repr_and_status_never_show_values():
    s = Secrets({"BACKBOARD_API_KEY": "super-secret-value-123", "WANDB_API_KEY": ""})
    assert "super-secret-value-123" not in repr(s)
    assert "super-secret-value-123" not in str(s)
    assert s.status().get("BACKBOARD_API_KEY") == "set"
    assert s.missing_required()  # WANDB keys empty
    assert "super-secret-value-123" not in s.scrub("x super-secret-value-123 y")
