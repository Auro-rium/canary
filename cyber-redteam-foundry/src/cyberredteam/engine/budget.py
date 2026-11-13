"""Central per-campaign budget (WP3): target requests and estimated LLM spend.

Every turn reserves one request *before* it is planned or sent, so parallel
conversations cannot all pass the check on the last request. After the send
the reservation is replaced by the real HTTP attempt count (SessionAdapter
retries count as requests). All charges are persisted through
``BudgetLedgerRepo``, so a resumed campaign starts from what it already spent.

Limits: ``CampaignPolicy.max_total_requests`` and ``max_llm_cost_usd``.
A reservation is refused once ``used + reserved >= max_total_requests``, or
once a non-zero LLM spend has reached ``max_llm_cost_usd`` (a cost-free
planner is never stopped by the USD limit, even when it is 0).
Known slack: one turn's retries (at most 2 extra attempts per in-flight turn)
can take the request total above the cap.
"""

from __future__ import annotations

import asyncio

from cyberredteam.contracts import BudgetUpdatePayload, CampaignPolicy
from cyberredteam.storage.v2.repositories import BudgetLedgerRepo


class BudgetLedger:
    def __init__(self, campaign_id: str, policy: CampaignPolicy, repo: BudgetLedgerRepo) -> None:
        self.campaign_id = campaign_id
        self._policy = policy
        self._repo = repo
        totals = repo.totals(campaign_id)
        self._requests = int(totals.get("requests", 0.0))
        self._tokens = int(totals.get("tokens", 0.0))
        self._usd = float(totals.get("usd", 0.0))
        self._reserved = 0
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

    def _usd_exhausted(self) -> bool:
        return self._usd > 0 and self._usd >= self._policy.max_llm_cost_usd

    def exhausted(self) -> bool:
        return self._requests + self._reserved >= self._policy.max_total_requests or self._usd_exhausted()

    def remaining_pct(self) -> float:
        """Smallest remaining share across the limits, in percent (0..100)."""
        req = 1.0 - self._requests / self._policy.max_total_requests
        shares = [req]
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

    async def reserve_request(self) -> bool:
        """Check before a turn. True means one request slot is now held."""
        async with self._lock:
            if self.exhausted():
                return False
            self._reserved += 1
            return True

    async def settle_request(self, attempts: int) -> None:
        """Replace a held slot with the real number of HTTP attempts (0 if unsent)."""
        async with self._lock:
            self._reserved = max(0, self._reserved - 1)
            if attempts > 0:
                self._repo.add(self.campaign_id, "requests", float(attempts))
                self._requests += attempts

    async def charge_llm(self, tokens: int, usd: float) -> None:
        if tokens <= 0 and usd <= 0:
            return
        async with self._lock:
            if tokens > 0:
                self._repo.add(self.campaign_id, "tokens", float(tokens))
                self._tokens += tokens
            if usd > 0:
                self._repo.add(self.campaign_id, "usd", float(usd))
                self._usd += usd
