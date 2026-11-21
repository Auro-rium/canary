"""Spend guard: a running USD total with a hard cap, checked BEFORE every step.

Why an estimate: Backboard reports tokens, not prices, and the judge's spend is
not charged to the campaign ledger (``max_llm_cost_usd`` only bounds planner
spend, which is $0 for the scripted planner). So the harness charges, per
conversation that may be judged::

    k votes x (1 + repair re-ask) x (input_tokens x rate_in + output_tokens x rate_out)

with the per-1k rates configured for the chosen judge model, and counts it against
the cap. ``reserve`` raises :class:`BudgetAbort` if the step could cross the budget
(default $4.50, under the $5 hard cap). After each step the harness may add
observed token usage parsed from the worker log, charging whichever is larger.
"""

from __future__ import annotations

from dataclasses import dataclass, field

HARD_CAP_USD = 5.00
DEFAULT_BUDGET_USD = 4.50
# Conservative sizing of one judge vote.
REPAIR_FACTOR = 2  # a failed structured parse triggers one billed re-ask
TOKENS_PER_TURN = 250
JUDGE_OUTPUT_TOKENS = 500
SCHEMA_OVERHEAD_TOKENS = 600
DOCTOR_PING_USD = 0.02


class BudgetAbort(RuntimeError):
    """The next step could push total spend over the budget."""


@dataclass
class Rates:
    usd_per_1k_in: float
    usd_per_1k_out: float


@dataclass
class SpendGuard:
    budget_usd: float = DEFAULT_BUDGET_USD
    rates: Rates = field(default_factory=lambda: Rates(0.003, 0.015))
    judge_votes: int = 3
    judge_prompt_tokens: int = 1500
    dry_run: bool = False
    spent_usd: float = 0.0  # what is charged against the cap (0 in dry-run)
    would_spend_usd: float = 0.0  # the same accounting at real rates (dry-run reporting)
    steps: dict[str, dict[str, float]] = field(default_factory=dict)
    held: dict[str, float] = field(default_factory=dict)  # reserved for launched, unsettled campaigns

    def __post_init__(self) -> None:
        if not 0 < self.budget_usd <= HARD_CAP_USD:
            raise ValueError(f"budget must be in (0, {HARD_CAP_USD}] USD")

    # -- estimates -----------------------------------------------------------------

    def vote_usd(self, turns: int) -> float:
        tin = self.judge_prompt_tokens + SCHEMA_OVERHEAD_TOKENS + TOKENS_PER_TURN * max(turns, 1)
        return (tin / 1000.0) * self.rates.usd_per_1k_in + (JUDGE_OUTPUT_TOKENS / 1000.0) * self.rates.usd_per_1k_out

    def conversation_usd(self, turns: int) -> float:
        """Worst case for judging one conversation."""
        return self.judge_votes * REPAIR_FACTOR * self.vote_usd(turns)

    def conversations_usd(self, conversations: int, turns: int) -> float:
        return conversations * self.conversation_usd(turns)

    # -- accounting ---------------------------------------------------------------

    @property
    def remaining_usd(self) -> float:
        return max(0.0, self.budget_usd - self.spent_usd)

    def _would_total(self) -> float:
        base = self.would_spend_usd if self.dry_run else self.spent_usd
        return base + sum(self.held.values())

    def hold(self, step: str, usd: float) -> None:
        """Keep ``usd`` reserved for a launched campaign until ``release`` settles the step."""
        self.held[step] = self.held.get(step, 0.0) + usd

    def release(self, step: str) -> None:
        self.held.pop(step, None)

    def reserve_check(self, step: str, estimate_usd: float) -> None:
        """Abort unless ``estimate_usd`` more fits under the budget (and the hard cap)."""
        projected = self._would_total() + estimate_usd
        if projected > self.budget_usd or projected > HARD_CAP_USD:
            raise BudgetAbort(
                f"step {step!r}: projected spend ${projected:.4f} would exceed the "
                f"${self.budget_usd:.2f} budget (spent ${self._would_total():.4f}, step estimate "
                f"${estimate_usd:.4f}); aborting before it runs"
            )

    def charge(self, step: str, usd: float, kind: str) -> None:
        if usd < 0:
            raise ValueError("negative charge")
        row = self.steps.setdefault(step, {})
        row[kind] = row.get(kind, 0.0) + usd
        self.would_spend_usd += usd
        # "would_*" kinds are estimates of spend that did not happen (judge not invoked on this
        # build); they never count against the cap in a real run.
        if not self.dry_run and not kind.startswith("would_"):
            self.spent_usd += usd

    def campaign_cap_usd(self, step_estimate_usd: float) -> float:
        """``max_llm_cost_usd`` for a campaign: what is left after this step's estimate,
        bounded by $0.50 (planner spend is $0 with the scripted planner), never below $0.01."""
        left = self._would_total() + step_estimate_usd
        return round(max(0.01, min(0.50, self.budget_usd - left)), 4)

    def step_total(self, step: str) -> float:
        """Charged USD for the step (excludes "would_*" estimates); in dry-run the would-be total."""
        row = self.steps.get(step, {})
        return sum(v for k, v in row.items() if self.dry_run or not k.startswith("would_"))

    def summary(self) -> dict:
        return {
            "budget_usd": self.budget_usd,
            "hard_cap_usd": HARD_CAP_USD,
            "dry_run": self.dry_run,
            "charged_usd": round(self.spent_usd, 6),
            "estimated_at_real_rates_usd": round(self.would_spend_usd, 6),
            "rates_usd_per_1k": {"in": self.rates.usd_per_1k_in, "out": self.rates.usd_per_1k_out},
            "judge_votes": self.judge_votes,
            "per_step_usd": {k: round(self.step_total(k), 6) for k, v in self.steps.items()},
            "per_step_detail_usd": {k: {kk: round(vv, 6) for kk, vv in v.items()} for k, v in self.steps.items()},
        }
