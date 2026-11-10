"""Shared helpers for the v2 storage tests (not collected by pytest)."""

from __future__ import annotations

import os
import uuid
from pathlib import Path

from alembic import command
from alembic.config import Config

from cyberredteam.contracts import (
    BearerAuth,
    CampaignPolicy,
    Conversation,
    ConversationVerdict,
    JudgeVote,
    TargetConfig,
    Turn,
)

ROOT = Path(__file__).resolve().parents[1]
PG_URL_ENV = "CANARY_TEST_DATABASE_URL"


def alembic_config(url: str) -> Config:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    return cfg


def migrate_up(url: str) -> None:
    command.upgrade(alembic_config(url), "head")


def migrate_down(url: str) -> None:
    command.downgrade(alembic_config(url), "base")


def pg_url() -> str | None:
    return os.environ.get(PG_URL_ENV)


def make_target(secret: str = "tok-SECRET-value-123", environment: str = "staging") -> TargetConfig:
    return TargetConfig(
        target_id=str(uuid.uuid4()),
        name="demo",
        endpoint="https://agent.example.com/chat",
        auth=BearerAuth(token=secret),
        session_mode="stateless_history",
        environment=environment,
    )


def make_policy() -> CampaignPolicy:
    return CampaignPolicy(techniques=["prompt_injection"], trials_per_technique=2)


def make_turn(conversation_id: str, index: int = 0, **kw) -> Turn:
    data = dict(
        conversation_id=conversation_id,
        index=index,
        message=f"hello {index}",
        response_text=f"reply {index}",
        latency_ms=12.5,
    )
    data.update(kw)
    return Turn(**data)


def make_conversation(campaign_id: str, trial: int = 0) -> Conversation:
    return Conversation(
        conversation_id=str(uuid.uuid4()),
        campaign_id=campaign_id,
        technique="prompt_injection",
        trial_index=trial,
    )


def make_verdict(conversation_id: str) -> ConversationVerdict:
    votes = [
        JudgeVote(vote_index=i, judgement="unsafe", confidence=0.9, severity="high",
                  rationale=f"vote {i} says unsafe", asi_class="ASI01", first_failing_turn=1)
        for i in range(3)
    ]
    return ConversationVerdict(
        conversation_id=conversation_id, verdict="confirmed", first_failing_turn=1,
        deterministic_hits=["canary_leak"], judge_votes=votes, judge_agreement=1.0,
        severity="high", asi_class="ASI01", rationale="leaked the canary",
    )
