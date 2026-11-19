"""Shared helpers for the test_engine_*.py suites (no tests here).

Everything is in-process: FakeTarget over httpx.MockTransport, a scripted
planner with benign placeholder messages, SQLite (and Postgres when
CANARY_TEST_DATABASE_URL is set). No real LLM, no network.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import pytest
from cryptography.fernet import Fernet
from fixtures.fake_target import FakeTarget
from pydantic import BaseModel
from storage_v2_support import migrate_down, migrate_up, pg_url
from test_session_adapter_support import FakeClock, NoLimit

from cyberredteam.contracts import CampaignPolicy, CampaignRequest
from cyberredteam.engine import (
    ConversationSpec,
    ConversationState,
    EngineDeps,
    EngineRepos,
    InMemoryRunControl,
    PlannedTurn,
)
from cyberredteam.storage.v2.db import make_engine, make_session_factory
from cyberredteam.storage.v2.encrypted import reset_key_cache
from cyberredteam.storage.v2.repositories import (
    BudgetLedgerRepo,
    CampaignRepo,
    ConversationRepo,
    SqlTargetStore,
)
from cyberredteam.transport import SessionAdapter

BACKENDS = ["sqlite", pytest.param("postgres", marks=pytest.mark.skipif(
    not pg_url(), reason="CANARY_TEST_DATABASE_URL not set"))]


@pytest.fixture(autouse=True)
def _key(monkeypatch):
    monkeypatch.setenv("CANARY_ENCRYPTION_KEY", Fernet.generate_key().decode())
    reset_key_cache()
    yield
    reset_key_cache()


@pytest.fixture(params=BACKENDS)
def factory(request, tmp_path):
    url = pg_url() if request.param == "postgres" else f"sqlite:///{tmp_path / 'v2.db'}"
    if request.param == "postgres":
        migrate_down(url)
    migrate_up(url)
    engine = make_engine(url)
    yield make_session_factory(engine)
    engine.dispose()
    if request.param == "postgres":
        migrate_down(url)


class ScriptedPlanner:
    """Benign fake planner: "hello turn N". Yields to the loop every turn so
    parallel conversations interleave. ``raise_at`` simulates a crash."""

    def __init__(self, *, raise_at: int | None = None, end_at: int | None = None,
                 cost_usd: float = 0.0, tokens: int = 0) -> None:
        self.raise_at = raise_at
        self.end_at = end_at
        self.cost_usd = cost_usd
        self.tokens = tokens
        self.states: list[ConversationState] = []

    async def next_turn(self, state: ConversationState) -> PlannedTurn | None:
        await asyncio.sleep(0)
        self.states.append(state)
        n = len(state.turns)
        if self.raise_at is not None and n == self.raise_at:
            raise RuntimeError("scripted planner crash")
        if self.end_at is not None and n == self.end_at:
            return None
        return PlannedTurn(message=f"hello turn {n}", intent_note="test",
                           llm_tokens=self.tokens, llm_cost_usd=self.cost_usd)


@dataclass
class Harness:
    factory: Any
    fake: FakeTarget
    request: CampaignRequest
    deps: EngineDeps
    control: InMemoryRunControl
    events: "HookSink"
    planners: list[ScriptedPlanner] = field(default_factory=list)
    active: int = 0
    max_active: int = 0
    transport: Any = None

    @property
    def conversations(self) -> ConversationRepo:
        return self.deps.repos.conversations


class HookSink:
    """Collecting event sink with an optional async hook per event."""

    def __init__(self) -> None:
        self.events: list[tuple[str, BaseModel]] = []
        self.hook: Callable[[str, BaseModel], Any] | None = None

    async def emit(self, event_type: str, payload: BaseModel) -> None:
        self.events.append((event_type, payload))
        if self.hook is not None:
            res = self.hook(event_type, payload)
            if asyncio.iscoroutine(res):
                await res

    def of_type(self, event_type: str) -> list[Any]:
        return [p for t, p in self.events if t == event_type]


def build(
    factory: Any,
    *,
    fake: FakeTarget | None = None,
    planner_kwargs: dict[str, Any] | None = None,
    techniques: list[str] | None = None,
    target_overrides: dict[str, Any] | None = None,
    sleep: Callable[[float], Any] | None = None,
    **policy: Any,
) -> Harness:
    fake = fake or FakeTarget()
    target = fake.target_config(**{"verified": True, **(target_overrides or {})})
    SqlTargetStore(factory).create(target)
    pol = {"techniques": techniques or ["technique_a"], "trials_per_technique": 1, "max_turns": 4}
    pol.update(policy)
    request = CampaignRequest(target=target, policy=CampaignPolicy(**pol))
    control = InMemoryRunControl()
    sink = HookSink()
    clock = FakeClock()
    harness: Harness

    def adapter_factory(cfg, campaign_id, limiter, before_attempt):
        adapter = SessionAdapter(cfg, campaign_id=campaign_id, rate_limiter=limiter,
                                 transport=harness.transport or fake.transport(),
                                 sleep=sleep or clock.sleep, clock=clock,
                                 before_attempt=before_attempt)
        harness.active += 1
        harness.max_active = max(harness.max_active, harness.active)
        original = adapter.aclose

        async def aclose():
            harness.active -= 1
            await original()

        adapter.aclose = aclose  # type: ignore[method-assign]
        return adapter

    def planner_factory(spec: ConversationSpec) -> ScriptedPlanner:
        planner = ScriptedPlanner(**(planner_kwargs or {}))
        harness.planners.append(planner)
        return planner

    deps = EngineDeps(
        repos=EngineRepos(
            conversations=ConversationRepo(factory),
            campaigns=CampaignRepo(factory),
            budget=BudgetLedgerRepo(factory),
        ),
        planner_factory=planner_factory,
        run_control=control,
        adapter_factory=adapter_factory,
        events=sink,
        rate_limiter=NoLimit(),
        clock=clock,
    )
    harness = Harness(factory=factory, fake=fake, request=request, deps=deps,
                      control=control, events=sink)
    return harness


def new_campaign_id() -> str:
    return f"camp-{uuid.uuid4().hex[:12]}"


class RecordingMetrics:
    def __init__(self) -> None:
        self.started: list[str] = []
        self.logs: list[tuple[str, dict[str, float], int | None]] = []
        self.finished: list[tuple[str, dict[str, Any]]] = []
        self.alerts: list[tuple[str, str, str]] = []

    def campaign_started(self, campaign_id, config):
        self.started.append(campaign_id)

    def log(self, campaign_id, metrics, step=None):
        self.logs.append((campaign_id, dict(metrics), step))

    def campaign_finished(self, campaign_id, summary):
        self.finished.append((campaign_id, dict(summary)))

    def alert(self, title, text, level="WARN"):
        self.alerts.append((title, text, level))


@pytest.fixture
def metrics():
    from cyberredteam.observability import hooks

    previous = hooks.get_metrics()
    rec = RecordingMetrics()
    hooks.set_metrics(rec)
    yield rec
    hooks.set_metrics(previous)
