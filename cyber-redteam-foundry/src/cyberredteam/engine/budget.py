"""Central per-campaign budget (WP3): target requests and estimated LLM spend.

Requests are charged one at a time *before* each outgoing HTTP request: every
attempt, every retry and every auth sub-request (token fetch, cookie login,
401 re-auth) goes through ``SessionAdapter``'s ``before_attempt`` hook, which
calls :meth:`BudgetLedger.charge_request`. So the request total can never
exceed ``CampaignPolicy.max_total_requests``, whatever the parallelism.

LLM spend (``max_llm_cost_usd``) is charged after each planner call; the limit
is checked before every turn and before every request, so one expensive
planner call can overshoot it, but no request is sent after that. A cost-free
planner is never stopped by the USD limit, even when the limit is 0.

Fail closed: the in-memory counters are updated first; if the ledger write to
``BudgetLedgerRepo`` fails, the budget counts as exhausted for the rest of
this run (and that request is refused). All charges are persisted, so a
resumed campaign starts from what it already spent.
"""

from __future__ import annotations

import asyncio
import logging

from cyberredteam.contracts import BudgetUpdatePayload, CampaignPolicy
from cyberredteam.storage.v2.repositories import BudgetLedgerRepo

logger = logging.getLogger(__name__)


class BudgetLedger:
    def __init__(self, campaign_id: str, policy: CampaignPolicy, repo: BudgetLedgerRepo) -> None:
        self.campaign_id = campaign_id
        self._policy = policy
        self._repo = repo
        totals = repo.totals(campaign_id)
        self._requests = int(totals.get("requests", 0.0))
        self._tokens = int(totals.get("tokens", 0.0))
        self._usd = float(totals.get("usd", 0.0))
        self._write_failed = False
        self._lock = asyncio.Lock()

    # ── State ────────────────────────────────────────────────────────────────

    @property
    def requests_used(self) -> int:
        return self._requests

    @property
    def llm_tokens(self) -> int:
        return self._tokens

    @property
    def llm_cost_usd(self) -> float:
        return self._usd

    @property
    def write_failed(self) -> bool:
        return self._write_failed

    def _usd_exhausted(self) -> bool:
        return self._usd > 0 and self._usd >= self._policy.max_llm_cost_usd

    def exhausted(self) -> bool:
        return (
            self._write_failed
            or self._requests >= self._policy.max_total_requests
            or self._usd_exhausted()
        )

    def remaining_pct(self) -> float:
        """Smallest remaining share across the limits, in percent (0..100)."""
        if self._write_failed:
            return 0.0
        shares = [1.0 - self._requests / self._policy.max_total_requests]
        if self._policy.max_llm_cost_usd > 0:
            shares.append(1.0 - self._usd / self._policy.max_llm_cost_usd)
        return max(0.0, min(shares)) * 100.0

    def snapshot(self) -> BudgetUpdatePayload:
        return BudgetUpdatePayload(
            campaign_id=self.campaign_id,
            requests_used=self._requests,
            max_total_requests=self._policy.max_total_requests,
            llm_cost_usd=self._usd,
            max_llm_cost_usd=self._policy.max_llm_cost_usd,
        )

    # ── Charging ─────────────────────────────────────────────────────────────

    def _persist(self, kind: str, amount: float) -> bool:
        try:
            self._repo.add(self.campaign_id, kind, amount)
            return True
        except Exception:
            logger.error("budget ledger write failed for %s; budget now exhausted", self.campaign_id)
            self._write_failed = True
            return False

    async def charge_request(self) -> bool:
        """Charge one HTTP request. False means it must not be sent."""
        async with self._lock:
            if self.exhausted():
                return False
            self._requests += 1
            return self._persist("requests", 1.0)

    async def charge_llm(self, tokens: int, usd: float) -> None:
        if tokens <= 0 and usd <= 0:
            return
        async with self._lock:
            if tokens > 0:
                self._tokens += tokens
                self._persist("tokens", float(tokens))
            if usd > 0:
                self._usd += usd
                self._persist("usd", float(usd))
