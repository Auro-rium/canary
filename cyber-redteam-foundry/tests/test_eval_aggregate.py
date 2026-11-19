"""B8: per-technique success rate with a Wilson 95% interval."""

from __future__ import annotations

import pytest

from cyberredteam.contracts import ConversationVerdict, TechniqueResult, wilson_interval
from cyberredteam.evaluation.aggregate import aggregate


@pytest.mark.parametrize(
    "k,n,low,high",
    [
        (5, 10, 0.2366, 0.7634),
        (0, 10, 0.0, 0.2775),
        (10, 10, 0.7225, 1.0),
        (1, 20, 0.0089, 0.2361),
        (0, 0, 0.0, 1.0),
    ],
)
def test_wilson_known_values(k, n, low, high):
    lo, hi = wilson_interval(k, n)
    assert lo == pytest.approx(low, abs=1e-4) and hi == pytest.approx(high, abs=1e-4)
    r = TechniqueResult.from_counts("t", n, k)
    assert (r.ci95_low, r.ci95_high) == (lo, hi)


def _v(verdict: str) -> ConversationVerdict:
    return ConversationVerdict(
        conversation_id="c", verdict=verdict, judge_agreement=1.0, severity="info", asi_class="ASI01"
    )


def test_aggregate_counts_and_exclusions():
    pairs = (
        [("a", _v("confirmed"))] * 5
        + [("a", _v("failed"))] * 4
        + [("a", _v("unconfirmed"))]
        + [("a", _v("inconclusive"))] * 3
        + [("a", None)]
        + [("b", _v("inconclusive"))] * 2
    )
    rep = aggregate(pairs)
    a, b = rep.results
    assert (a.technique, a.trials, a.confirmed, a.success_rate) == ("a", 10, 5, 0.5)
    assert a.ci95_low == pytest.approx(0.2366, abs=1e-4)
    assert rep.tallies["a"].inconclusive == 3 and rep.tallies["a"].no_verdict == 1
    # All-inconclusive technique: unknown, not "safe".
    assert (b.trials, b.ci95_low, b.ci95_high) == (0, 0.0, 1.0)
