"""Org-isolation lookups (WP8).

Every v2 object is owned through its target: campaign -> target, conversation ->
campaign -> target, finding -> target. A target with ``org_id`` NULL belongs to
no org. Callers turn a ``None`` here into a 404, so another org's objects are
indistinguishable from missing ones.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from cyberredteam.storage.v2 import orm
from cyberredteam.storage.v2.db import session_scope


def target_in_org(factory: sessionmaker[Session], target_id: str, org_id: str) -> bool:
    with session_scope(factory) as s:
        found = s.scalar(
            select(orm.TargetRow.target_id).where(
                orm.TargetRow.target_id == target_id, orm.TargetRow.org_id == org_id
            )
        )
        return found is not None


def campaign_in_org(factory: sessionmaker[Session], campaign_id: str, org_id: str) -> bool:
    with session_scope(factory) as s:
        found = s.scalar(
            select(orm.CampaignRow.campaign_id)
            .join(orm.TargetRow, orm.TargetRow.target_id == orm.CampaignRow.target_id)
            .where(orm.CampaignRow.campaign_id == campaign_id, orm.TargetRow.org_id == org_id)
        )
        return found is not None


def conversation_in_org(factory: sessionmaker[Session], conversation_id: str, org_id: str) -> bool:
    with session_scope(factory) as s:
        found = s.scalar(
            select(orm.ConversationRow.conversation_id)
            .join(orm.CampaignRow, orm.CampaignRow.campaign_id == orm.ConversationRow.campaign_id)
            .join(orm.TargetRow, orm.TargetRow.target_id == orm.CampaignRow.target_id)
            .where(
                orm.ConversationRow.conversation_id == conversation_id,
                orm.TargetRow.org_id == org_id,
            )
        )
        return found is not None


def finding_in_org(factory: sessionmaker[Session], finding_id: str, org_id: str) -> bool:
    with session_scope(factory) as s:
        found = s.scalar(
            select(orm.FindingRow.finding_id)
            .join(orm.TargetRow, orm.TargetRow.target_id == orm.FindingRow.target_id)
            .where(orm.FindingRow.finding_id == finding_id, orm.TargetRow.org_id == org_id)
        )
        return found is not None
