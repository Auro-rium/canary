"""Evidence retention purge.

Turn evidence (encrypted ``message`` and ``response_text``) older than the
target's retention window is wiped. The turn row, its redacted previews and
metadata stay, so verdicts and foreign keys remain valid.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.orm import Session, sessionmaker

from cyberredteam.settings import get_settings
from cyberredteam.storage.v2 import orm
from cyberredteam.storage.v2.db import session_scope

logger = logging.getLogger(__name__)


def purge_expired_evidence(
    factory: sessionmaker[Session],
    *,
    now: datetime | None = None,
    default_days: int | None = None,
) -> dict[str, int]:
    """Wipe raw evidence past retention. Returns ``{"targets_scanned", "turns_purged"}``.

    Each target uses its own ``retention_days`` if set, else ``default_days``
    (default: ``Settings.evidence_retention_days``). Idempotent."""
    now = now or datetime.now(timezone.utc)
    if default_days is None:
        default_days = get_settings().evidence_retention_days
    scanned = purged = 0
    with session_scope(factory) as s:
        for target_id, override in s.execute(
            select(orm.TargetRow.target_id, orm.TargetRow.retention_days)
        ).all():
            scanned += 1
            days = override if override is not None else default_days
            cutoff = now - timedelta(days=days)
            conv_ids = (
                select(orm.ConversationRow.conversation_id)
                .join(orm.CampaignRow, orm.CampaignRow.campaign_id == orm.ConversationRow.campaign_id)
                .where(orm.CampaignRow.target_id == target_id)
            )
            result = s.execute(
                update(orm.TurnRow)
                .where(
                    orm.TurnRow.conversation_id.in_(conv_ids),
                    orm.TurnRow.created_at < cutoff,
                    orm.TurnRow.purged_at.is_(None),
                )
                .values(message=None, response_text=None, purged_at=now)
            )
            purged += result.rowcount or 0
        s.add(
            orm.AuditLogRow(
                actor="system",
                action="retention.purge",
                object="turns",
                details={"turns_purged": purged, "targets_scanned": scanned},
            )
        )
    logger.info("retention purge turns_purged=%d targets_scanned=%d", purged, scanned)
    return {"targets_scanned": scanned, "turns_purged": purged}
