"""Repositories for the v2 data layer.

Each repository takes a ``sessionmaker`` and opens a short transaction per call,
so every write is durable as soon as the method returns (``append_turn`` in
particular). They accept and return ``contracts.py`` models; the few records
contracts.py does not define (campaign row, finding) are small models here.

Raw evidence is never logged. Reads that return it (``ConversationRepo.get``
with ``raw=True``) require an actor and write an audit row.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any, Literal, get_args

from pydantic import BaseModel, ConfigDict, SecretStr, TypeAdapter
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError, StatementError
from sqlalchemy.orm import Session, sessionmaker

from cyberredteam.contracts import (
    AsiCode,
    CampaignPolicy,
    Conversation,
    ConversationStatus,
    ConversationVerdict,
    JudgeVote,
    Severity,
    TargetAuth,
    TargetConfig,
    TechniqueResult,
    ToolCallObservation,
    Turn,
    truncate_preview,
)
from cyberredteam.storage.v2 import orm
from cyberredteam.storage.v2.db import session_scope
from cyberredteam.storage.v2.redaction import redact

logger = logging.getLogger(__name__)

_AUTH_ADAPTER: TypeAdapter = TypeAdapter(TargetAuth)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


_SECRET_SEGMENTS = frozenset(
    {"password", "passwd", "pwd", "pass", "passphrase", "secret", "secrets", "credential",
     "credentials", "authorization", "cookie", "cookies", "apikey", "token", "bearer"}
)
_SECRET_PAIRS = frozenset({("api", "key"), ("private", "key"), ("access", "key"), ("secret", "key")})
_COUNT_NEIGHBOURS = frozenset(
    {"max", "min", "total", "num", "prompt", "completion", "input", "output", "count", "limit",
     "usage", "used", "budget", "remaining", "estimate", "est"}
)


def _is_sensitive_key(key: str) -> bool:
    """True for secret-looking keys (password, api_key, accessToken, ...). Token-count
    style keys (max_tokens, token_count, tokens_used) are not secrets."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key).lower()
    parts = [p for p in re.split(r"[^a-z0-9]+", spaced) if p]
    for i, seg in enumerate(parts):
        if seg in _SECRET_SEGMENTS:
            if seg == "token" and (
                (i > 0 and parts[i - 1] in _COUNT_NEIGHBOURS)
                or (i + 1 < len(parts) and parts[i + 1] in _COUNT_NEIGHBOURS)
            ):
                continue
            return True
        if i + 1 < len(parts) and (seg, parts[i + 1]) in _SECRET_PAIRS:
            return True
    return False


def _redact_obj(value: Any, canary_values: tuple[str, ...] = ()) -> Any:
    """Redact every string inside a JSON-like structure. Whatever sits under a
    secret-looking key (string, number, list or dict) is masked outright."""
    if isinstance(value, str):
        return redact(value, canary_values).text
    if isinstance(value, dict):
        return {
            str(k): (
                "[REDACTED:secret]"
                if v is not None and _is_sensitive_key(str(k))
                else _redact_obj(v, canary_values)
            )
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_redact_obj(v, canary_values) for v in value]
    return value


def _audit_row(
    actor: str, action: str, obj: str, details: dict[str, Any] | None = None
) -> orm.AuditLogRow:
    return orm.AuditLogRow(
        actor=actor, action=action, object=obj, details=_redact_obj(details or {})
    )


# ── Targets ──────────────────────────────────────────────────────────────────


def _raise_key_error(exc: StatementError) -> None:
    """A missing encryption key surfaces inside SQLAlchemy as a StatementError;
    re-raise it as the plain ``RuntimeError`` callers handle (fail closed)."""
    if isinstance(exc.orig, RuntimeError):
        raise RuntimeError(str(exc.orig)) from None
    raise exc


class TargetMeta(BaseModel):
    """Target facts that are not part of the frozen ``TargetConfig`` contract (WP8)."""

    model_config = ConfigDict(extra="forbid")

    target_id: str
    org_id: str | None
    archived: bool
    verified_method: str | None
    verified_at: datetime | None
    has_oncall_webhook: bool
    created_at: datetime | None


class SqlTargetStore:
    """Targets, their encrypted secrets and ownership-verification state."""

    def __init__(self, factory: sessionmaker[Session]) -> None:
        self._factory = factory

    @property
    def factory(self) -> sessionmaker[Session]:
        return self._factory

    @staticmethod
    def _split_auth(config: TargetConfig) -> tuple[dict, dict]:
        public = config.auth.model_dump(mode="json")
        secrets: dict[str, str] = {}
        for name, value in config.auth:
            if isinstance(value, SecretStr):
                secrets[name] = value.get_secret_value()
                public.pop(name, None)
        return public, secrets

    def create(
        self,
        config: TargetConfig,
        *,
        org_id: str | None = None,
        oncall_webhook: str | None = None,
    ) -> str:
        """Store a target. ``verified`` is always stored False: only ``set_verified`` flips it.

        ``org_id`` scopes it to an org (WP8); ``None`` means visible to no org."""
        public, secrets = self._split_auth(config)
        row = orm.TargetRow(
            target_id=config.target_id,
            name=config.name,
            endpoint=str(config.endpoint),
            method=config.method,
            auth_public=public,
            request_template=config.request_template,
            response_path=config.response_path,
            session_mode=config.session_mode,
            session_id_path=config.session_id_path,
            tool_trace_path=config.tool_trace_path,
            streaming=config.streaming,
            timeout_s=config.timeout_s,
            verified=False,
            environment=config.environment,
            org_id=org_id,
            oncall_webhook=oncall_webhook or None,
        )
        try:
            with session_scope(self._factory) as s:
                s.add(row)
                s.flush()
                if secrets:
                    s.add(orm.TargetSecretRow(target_id=config.target_id, secrets=json.dumps(secrets)))
        except IntegrityError as exc:
            raise ValueError(f"target {config.target_id} already exists") from exc
        except StatementError as exc:
            _raise_key_error(exc)
        logger.info("target created target_id=%s", config.target_id)
        return config.target_id

    def _to_config(self, s: Session, row: orm.TargetRow) -> TargetConfig:
        secret_row = s.get(orm.TargetSecretRow, row.target_id)
        secrets = json.loads(secret_row.secrets) if secret_row else {}
        auth = _AUTH_ADAPTER.validate_python({**row.auth_public, **secrets})
        return TargetConfig(
            target_id=row.target_id,
            name=row.name,
            endpoint=row.endpoint,
            method=row.method,
            auth=auth,
            request_template=row.request_template,
            response_path=row.response_path,
            session_mode=row.session_mode,
            session_id_path=row.session_id_path,
            tool_trace_path=row.tool_trace_path,
            streaming=row.streaming,
            timeout_s=row.timeout_s,
            verified=row.verified,
            environment=row.environment,
        )

    def get(self, target_id: str) -> TargetConfig | None:
        with session_scope(self._factory) as s:
            row = s.get(orm.TargetRow, target_id)
            return self._to_config(s, row) if row else None

    def list(self) -> list[TargetConfig]:
        with session_scope(self._factory) as s:
            rows = s.scalars(select(orm.TargetRow).order_by(orm.TargetRow.created_at)).all()
            return [self._to_config(s, r) for r in rows]

    def set_verified(self, target_id: str, method: str) -> None:
        now = _utcnow()
        with session_scope(self._factory) as s:
            row = s.get(orm.TargetRow, target_id)
            if row is None:
                raise KeyError(target_id)
            row.verified = True
            ver = s.get(orm.TargetVerificationRow, target_id)
            if ver is None:
                ver = orm.TargetVerificationRow(target_id=target_id)
                s.add(ver)
            ver.method = method
            ver.verified_at = now
        logger.info("target verified target_id=%s method=%s", target_id, method)

    def set_verification_token_hash(self, target_id: str, token_hash: str) -> None:
        with session_scope(self._factory) as s:
            if s.get(orm.TargetRow, target_id) is None:
                raise KeyError(target_id)
            ver = s.get(orm.TargetVerificationRow, target_id)
            if ver is None:
                s.add(orm.TargetVerificationRow(target_id=target_id, token_hash=token_hash))
            else:
                ver.token_hash = token_hash

    def get_verification_token_hash(self, target_id: str) -> str | None:
        with session_scope(self._factory) as s:
            ver = s.get(orm.TargetVerificationRow, target_id)
            return ver.token_hash if ver else None

    def set_allowed_auth_hosts(self, target_id: str, hosts: list[str]) -> None:
        """Hosts credentials may be sent to (lower-cased, de-duplicated, order kept)."""
        clean = list(dict.fromkeys(h.strip().lower() for h in hosts if h and h.strip()))
        with session_scope(self._factory) as s:
            if s.get(orm.TargetRow, target_id) is None:
                raise KeyError(target_id)
            ver = s.get(orm.TargetVerificationRow, target_id)
            if ver is None:
                s.add(orm.TargetVerificationRow(target_id=target_id, allowed_auth_hosts=clean))
            else:
                ver.allowed_auth_hosts = clean

    def get_allowed_auth_hosts(self, target_id: str) -> list[str]:
        with session_scope(self._factory) as s:
            ver = s.get(orm.TargetVerificationRow, target_id)
            return list(ver.allowed_auth_hosts or []) if ver else []

    # ── WP8: org scope, update, archive/delete, on-call webhook ──────────────

    def meta(self, target_id: str) -> TargetMeta | None:
        with session_scope(self._factory) as s:
            row = s.get(orm.TargetRow, target_id)
            if row is None:
                return None
            ver = s.get(orm.TargetVerificationRow, target_id)
            return TargetMeta(
                target_id=row.target_id,
                org_id=row.org_id,
                archived=row.archived_at is not None,
                verified_method=ver.method if ver else None,
                verified_at=ver.verified_at if ver else None,
                has_oncall_webhook=bool(row.oncall_webhook),
                created_at=row.created_at,
            )

    def get_in_org(self, target_id: str, org_id: str) -> TargetConfig | None:
        """The target only if it belongs to ``org_id`` and is not archived."""
        with session_scope(self._factory) as s:
            row = s.get(orm.TargetRow, target_id)
            if row is None or row.org_id is None or row.org_id != org_id or row.archived_at:
                return None
            return self._to_config(s, row)

    def list_for_org(self, org_id: str) -> list[TargetConfig]:
        with session_scope(self._factory) as s:
            rows = s.scalars(
                select(orm.TargetRow)
                .where(orm.TargetRow.org_id == org_id, orm.TargetRow.archived_at.is_(None))
                .order_by(orm.TargetRow.created_at)
            ).all()
            return [self._to_config(s, r) for r in rows]

    def update(self, config: TargetConfig, *, reset_verification: bool) -> None:
        """Replace a target's stored config (secrets included).

        ``verified`` is never taken from ``config``; ``reset_verification=True``
        clears it (the caller decides which changes require re-verification)."""
        public, secrets = self._split_auth(config)
        try:
            self._update(config, public, secrets, reset_verification)
        except StatementError as exc:
            _raise_key_error(exc)
        logger.info("target updated target_id=%s reset=%s", config.target_id, reset_verification)

    def _update(self, config: TargetConfig, public: dict, secrets: dict, reset_verification: bool) -> None:
        with session_scope(self._factory) as s:
            row = s.get(orm.TargetRow, config.target_id, with_for_update=True)
            if row is None:
                raise KeyError(config.target_id)
            row.name = config.name
            row.endpoint = str(config.endpoint)
            row.method = config.method
            row.auth_public = public
            row.request_template = config.request_template
            row.response_path = config.response_path
            row.session_mode = config.session_mode
            row.session_id_path = config.session_id_path
            row.tool_trace_path = config.tool_trace_path
            row.streaming = config.streaming
            row.timeout_s = config.timeout_s
            row.environment = config.environment
            if reset_verification:
                row.verified = False
                ver = s.get(orm.TargetVerificationRow, config.target_id)
                if ver is not None:
                    ver.method = None
                    ver.verified_at = None
            secret_row = s.get(orm.TargetSecretRow, config.target_id)
            if secrets:
                if secret_row is None:
                    s.add(orm.TargetSecretRow(target_id=config.target_id, secrets=json.dumps(secrets)))
                else:
                    secret_row.secrets = json.dumps(secrets)
                    secret_row.updated_at = _utcnow()
            elif secret_row is not None:
                s.delete(secret_row)

    def set_oncall_webhook(self, target_id: str, url: str | None) -> None:
        with session_scope(self._factory) as s:
            row = s.get(orm.TargetRow, target_id)
            if row is None:
                raise KeyError(target_id)
            row.oncall_webhook = url or None

    def get_oncall_webhook(self, target_id: str) -> str | None:
        with session_scope(self._factory) as s:
            row = s.get(orm.TargetRow, target_id)
            return row.oncall_webhook if row else None

    def has_campaigns(self, target_id: str, *, active_only: bool = False) -> bool:
        with session_scope(self._factory) as s:
            q = select(func.count()).select_from(orm.CampaignRow).where(
                orm.CampaignRow.target_id == target_id
            )
            if active_only:
                q = q.where(orm.CampaignRow.status.not_in(TERMINAL_CAMPAIGN_STATUSES))
            return bool(s.scalar(q))

    def archive(self, target_id: str) -> None:
        """Soft delete: hidden from every org and unverified, so nothing can run on it."""
        with session_scope(self._factory) as s:
            row = s.get(orm.TargetRow, target_id)
            if row is None:
                raise KeyError(target_id)
            row.archived_at = row.archived_at or _utcnow()
            row.verified = False
            row.oncall_webhook = None
            secret_row = s.get(orm.TargetSecretRow, target_id)
            if secret_row is not None:  # credentials are no longer needed
                s.delete(secret_row)
                row.auth_public = {"type": "none"}

    def delete(self, target_id: str) -> None:
        """Hard delete (secrets and verification cascade). Raises ``ValueError``
        if campaigns or findings still reference the target (use ``archive``)."""
        try:
            with session_scope(self._factory) as s:
                row = s.get(orm.TargetRow, target_id)
                if row is None:
                    raise KeyError(target_id)
                for child in (orm.TargetSecretRow, orm.TargetVerificationRow):
                    c = s.get(child, target_id)
                    if c is not None:
                        s.delete(c)
                s.flush()
                s.delete(row)
        except IntegrityError as exc:
            raise ValueError("target is still referenced") from exc

    def set_retention_days(self, target_id: str, days: int | None) -> None:
        """Per-target evidence retention override (None → global default)."""
        if days is not None and days < 0:
            raise ValueError("retention days must be >= 0")
        with session_scope(self._factory) as s:
            row = s.get(orm.TargetRow, target_id)
            if row is None:
                raise KeyError(target_id)
            row.retention_days = days


# ── Campaigns ────────────────────────────────────────────────────────────────


class CampaignRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    campaign_id: str
    target_id: str
    policy: CampaignPolicy
    status: CampaignStatus = "queued"
    created_by: str | None = None
    created_at: datetime | None = None
    finished_at: datetime | None = None


CampaignStatus = Literal["queued", "running", "completed", "failed", "cancelled"]
CAMPAIGN_STATUSES = frozenset(get_args(CampaignStatus))
TERMINAL_CAMPAIGN_STATUSES = frozenset({"completed", "failed", "cancelled"})


class CampaignRepo:
    def __init__(self, factory: sessionmaker[Session]) -> None:
        self._factory = factory

    @staticmethod
    def _rec(row: orm.CampaignRow) -> CampaignRecord:
        return CampaignRecord(
            campaign_id=row.campaign_id,
            target_id=row.target_id,
            policy=CampaignPolicy.model_validate(row.policy),
            status=row.status,
            created_by=row.created_by,
            created_at=row.created_at,
            finished_at=row.finished_at,
        )

    def create(
        self, campaign_id: str, target_id: str, policy: CampaignPolicy, created_by: str | None = None
    ) -> CampaignRecord:
        with session_scope(self._factory) as s:
            row = orm.CampaignRow(
                campaign_id=campaign_id,
                target_id=target_id,
                policy=policy.model_dump(mode="json"),
                created_by=created_by,
            )
            s.add(row)
            s.flush()
            return self._rec(row)

    def get(self, campaign_id: str) -> CampaignRecord | None:
        with session_scope(self._factory) as s:
            row = s.get(orm.CampaignRow, campaign_id)
            return self._rec(row) if row else None

    def set_status(self, campaign_id: str, status: CampaignStatus) -> None:
        with session_scope(self._factory) as s:
            if status not in CAMPAIGN_STATUSES:
                raise ValueError(f"unknown campaign status {status!r}")
            row = s.get(orm.CampaignRow, campaign_id)
            if row is None:
                raise KeyError(campaign_id)
            row.status = status
            if status in TERMINAL_CAMPAIGN_STATUSES:
                row.finished_at = _utcnow()

    def list_for_target(self, target_id: str) -> list[CampaignRecord]:
        with session_scope(self._factory) as s:
            rows = s.scalars(
                select(orm.CampaignRow)
                .where(orm.CampaignRow.target_id == target_id)
                .order_by(orm.CampaignRow.created_at)
            ).all()
            return [self._rec(r) for r in rows]

    def save_technique_results(self, campaign_id: str, results: Iterable[TechniqueResult]) -> None:
        with session_scope(self._factory) as s:
            existing = {
                r.technique: r
                for r in s.scalars(
                    select(orm.TechniqueResultRow).where(
                        orm.TechniqueResultRow.campaign_id == campaign_id
                    )
                )
            }
            for res in results:
                row = existing.get(res.technique)
                if row is None:
                    row = orm.TechniqueResultRow(campaign_id=campaign_id, technique=res.technique)
                    s.add(row)
                row.trials = res.trials
                row.confirmed = res.confirmed
                row.success_rate = res.success_rate
                row.ci95_low = res.ci95_low
                row.ci95_high = res.ci95_high

    def technique_results(self, campaign_id: str) -> list[TechniqueResult]:
        with session_scope(self._factory) as s:
            rows = s.scalars(
                select(orm.TechniqueResultRow)
                .where(orm.TechniqueResultRow.campaign_id == campaign_id)
                .order_by(orm.TechniqueResultRow.technique)
            ).all()
            return [
                TechniqueResult(
                    technique=r.technique,
                    trials=r.trials,
                    confirmed=r.confirmed,
                    success_rate=r.success_rate,
                    ci95_low=r.ci95_low,
                    ci95_high=r.ci95_high,
                )
                for r in rows
            ]


# ── Conversations and turns ──────────────────────────────────────────────────


class ConversationRepo:
    def __init__(self, factory: sessionmaker[Session]) -> None:
        self._factory = factory

    def create(self, conversation: Conversation, canary_values: Iterable[str] = ()) -> None:
        """Insert a conversation (and any turns it already carries)."""
        with session_scope(self._factory) as s:
            s.add(
                orm.ConversationRow(
                    conversation_id=conversation.conversation_id,
                    campaign_id=conversation.campaign_id,
                    technique=conversation.technique,
                    trial_index=conversation.trial_index,
                    status=conversation.status,
                    target_session_ref=conversation.target_session_ref,
                )
            )
            s.flush()
            for turn in conversation.turns:
                s.add(self._turn_row(turn, canary_values))

    @staticmethod
    def _turn_row(turn: Turn, canary_values: Iterable[str]) -> orm.TurnRow:
        canaries = tuple(canary_values)
        msg = redact(turn.message, canaries)
        resp = redact(turn.response_text, canaries)
        err = redact(turn.error, canaries).text if turn.error else None
        hits = list(dict.fromkeys([*msg.hits, *resp.hits]))
        return orm.TurnRow(
            conversation_id=turn.conversation_id,
            idx=turn.index,
            role_sent=turn.role_sent,
            message=turn.message,
            response_text=turn.response_text,
            redacted_message_preview=truncate_preview(msg.text) or "",
            redacted_preview=truncate_preview(resp.text) or "",
            redaction_hits=hits,
            tool_calls=_redact_obj([t.model_dump(mode="json") for t in turn.tool_calls], canaries),
            tool_calls_raw=json.dumps([t.model_dump(mode="json") for t in turn.tool_calls]),
            http_status=turn.http_status,
            latency_ms=turn.latency_ms,
            monitor_hits=list(turn.monitor_hits),
            error=err,
        )

    def append_turn(self, turn: Turn, canary_values: Iterable[str] = ()) -> None:
        """Persist one turn immediately (committed before returning): encrypted
        evidence plus plaintext redacted previews."""
        with session_scope(self._factory) as s:
            s.add(self._turn_row(turn, canary_values))

    def set_status(
        self, conversation_id: str, status: ConversationStatus, target_session_ref: str | None = None
    ) -> None:
        if status not in get_args(ConversationStatus):
            raise ValueError(f"unknown conversation status {status!r}")
        with session_scope(self._factory) as s:
            row = s.get(orm.ConversationRow, conversation_id)
            if row is None:
                raise KeyError(conversation_id)
            row.status = status
            if target_session_ref is not None:
                row.target_session_ref = target_session_ref

    def get(
        self, conversation_id: str, *, raw: bool = False, actor: str | None = None
    ) -> Conversation | None:
        """Load a conversation. By default turn text is the redacted preview;
        ``raw=True`` returns decrypted evidence, needs ``actor`` and is audited."""
        if raw and not actor:
            raise ValueError("raw evidence access requires an actor")
        with session_scope(self._factory) as s:
            row = s.get(orm.ConversationRow, conversation_id)
            if row is None:
                return None
            turns = s.scalars(
                select(orm.TurnRow)
                .where(orm.TurnRow.conversation_id == conversation_id)
                .order_by(orm.TurnRow.idx)
            ).all()
            if raw:
                s.add(
                    _audit_row(
                        actor or "",
                        "evidence.read_raw",
                        f"conversation:{conversation_id}",
                        {"turns": len(turns)},
                    )
                )
            return Conversation(
                conversation_id=row.conversation_id,
                campaign_id=row.campaign_id,
                technique=row.technique,
                trial_index=row.trial_index,
                status=row.status,
                target_session_ref=row.target_session_ref,
                turns=[self._turn(t, raw) for t in turns],
            )

    @staticmethod
    def _turn(t: orm.TurnRow, raw: bool) -> Turn:
        calls = t.tool_calls
        if raw:
            message, response = t.message or "", t.response_text or ""
            if t.tool_calls_raw is not None:
                calls = json.loads(t.tool_calls_raw)
        else:
            message, response = t.redacted_message_preview, t.redacted_preview
        return Turn(
            conversation_id=t.conversation_id,
            index=t.idx,
            role_sent=t.role_sent,
            message=message,
            response_text=response,
            tool_calls=[ToolCallObservation.model_validate(tc) for tc in calls],
            http_status=t.http_status,
            latency_ms=t.latency_ms,
            monitor_hits=list(t.monitor_hits),
            error=t.error,
        )

    def list_for_campaign(self, campaign_id: str) -> list[str]:
        with session_scope(self._factory) as s:
            return list(
                s.scalars(
                    select(orm.ConversationRow.conversation_id)
                    .where(orm.ConversationRow.campaign_id == campaign_id)
                    .order_by(orm.ConversationRow.technique, orm.ConversationRow.trial_index)
                )
            )


# ── Verdicts ─────────────────────────────────────────────────────────────────


class VerdictRepo:
    def __init__(self, factory: sessionmaker[Session]) -> None:
        self._factory = factory

    def save(self, verdict: ConversationVerdict) -> None:
        """Insert or replace the verdict and its judge votes."""
        cid = verdict.conversation_id
        with session_scope(self._factory) as s:
            row = s.get(orm.VerdictRow, cid)
            if row is None:
                row = orm.VerdictRow(conversation_id=cid)
                s.add(row)
            row.verdict = verdict.verdict
            row.first_failing_turn = verdict.first_failing_turn
            row.deterministic_hits = list(verdict.deterministic_hits)
            row.judge_agreement = verdict.judge_agreement
            row.severity = verdict.severity
            row.asi_class = verdict.asi_class
            row.rationale = verdict.rationale
            for old in s.scalars(
                select(orm.JudgeVoteRow).where(orm.JudgeVoteRow.conversation_id == cid)
            ):
                s.delete(old)
            s.flush()
            for v in verdict.judge_votes:
                s.add(
                    orm.JudgeVoteRow(
                        conversation_id=cid,
                        vote_index=v.vote_index,
                        judgement=v.judgement,
                        first_failing_turn=v.first_failing_turn,
                        asi_class=v.asi_class,
                        severity=v.severity,
                        confidence=v.confidence,
                        rationale=v.rationale,
                        model_name=v.model_name,
                        temperature=v.temperature,
                    )
                )

    @staticmethod
    def _load(s: Session, conversation_id: str, raw: bool) -> ConversationVerdict | None:
        row = s.get(orm.VerdictRow, conversation_id)
        if row is None:
            return None
        votes = s.scalars(
            select(orm.JudgeVoteRow)
            .where(orm.JudgeVoteRow.conversation_id == conversation_id)
            .order_by(orm.JudgeVoteRow.vote_index)
        ).all()

        def txt(value: str) -> str:
            return value if raw else redact(value).text

        return ConversationVerdict(
            conversation_id=conversation_id,
            verdict=row.verdict,
            first_failing_turn=row.first_failing_turn,
            deterministic_hits=list(row.deterministic_hits),
            judge_agreement=row.judge_agreement,
            severity=row.severity,
            asi_class=row.asi_class,
            rationale=txt(row.rationale),
            judge_votes=[
                JudgeVote(
                    vote_index=v.vote_index,
                    judgement=v.judgement,
                    first_failing_turn=v.first_failing_turn,
                    asi_class=v.asi_class,
                    severity=v.severity,
                    confidence=v.confidence,
                    rationale=txt(v.rationale),
                    model_name=v.model_name,
                    temperature=v.temperature,
                )
                for v in votes
            ],
        )

    def get(
        self, conversation_id: str, *, raw: bool = False, actor: str | None = None
    ) -> ConversationVerdict | None:
        """Load a verdict. Rationales are redacted by default; ``raw=True`` needs
        ``actor`` and writes an ``evidence.read_raw`` audit row."""
        if raw and not actor:
            raise ValueError("raw evidence access requires an actor")
        with session_scope(self._factory) as s:
            verdict = self._load(s, conversation_id, raw)
            if raw and verdict is not None:
                s.add(_audit_row(actor or "", "evidence.read_raw", f"verdict:{conversation_id}"))
            return verdict

    def list_for_campaign(
        self, campaign_id: str, *, raw: bool = False, actor: str | None = None
    ) -> list[ConversationVerdict]:
        if raw and not actor:
            raise ValueError("raw evidence access requires an actor")
        with session_scope(self._factory) as s:
            ids = list(
                s.scalars(
                    select(orm.VerdictRow.conversation_id)
                    .join(
                        orm.ConversationRow,
                        orm.ConversationRow.conversation_id == orm.VerdictRow.conversation_id,
                    )
                    .where(orm.ConversationRow.campaign_id == campaign_id)
                    .order_by(orm.ConversationRow.technique, orm.ConversationRow.trial_index)
                )
            )
            out = [v for v in (self._load(s, i, raw) for i in ids) if v is not None]
            if raw and out:
                s.add(
                    _audit_row(
                        actor or "", "evidence.read_raw", f"campaign:{campaign_id}",
                        {"verdicts": len(out)},
                    )
                )
            return out


# ── Findings ─────────────────────────────────────────────────────────────────

FindingStatus = Literal["open", "wont_fix", "false_positive", "inconclusive", "needs_review"]
FINDING_TRANSITIONS: dict[str, frozenset[str]] = {
    "open": frozenset({"wont_fix", "false_positive", "inconclusive", "needs_review"}),
    "inconclusive": frozenset({"open", "wont_fix", "false_positive"}),
    "needs_review": frozenset({"open", "wont_fix", "false_positive"}),
    "wont_fix": frozenset(),
    "false_positive": frozenset(),
}
TERMINAL_FINDING_STATUSES = frozenset({"wont_fix", "false_positive"})
_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
DEDUP_THRESHOLD = 0.92


class InvalidTransition(ValueError):
    pass


class FindingRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    target_id: str
    component: str = ""
    technique: str = ""
    asi_class: AsiCode
    severity: Severity
    status: FindingStatus = "open"
    title: str = ""
    first_seen_campaign: str | None = None
    last_seen_campaign: str | None = None
    seen_in_campaigns: list[str] = []
    conversation_id: str | None = None


class FindingEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    from_status: FindingStatus | None
    to_status: FindingStatus
    reviewer_id: str | None
    rationale: str | None
    at: datetime


def _cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = sum(x * x for x in a) ** 0.5
    nb = sum(y * y for y in b) ** 0.5
    return dot / (na * nb) if na and nb else 0.0


class FindingRepo:
    def __init__(self, factory: sessionmaker[Session]) -> None:
        self._factory = factory

    @staticmethod
    def _rec(row: orm.FindingRow) -> FindingRecord:
        return FindingRecord(
            finding_id=row.finding_id,
            target_id=row.target_id,
            component=row.component,
            technique=row.technique,
            asi_class=row.asi_class,
            severity=row.severity,
            status=row.status,
            title=row.title,
            first_seen_campaign=row.first_seen_campaign,
            last_seen_campaign=row.last_seen_campaign,
            seen_in_campaigns=list(row.seen_in_campaigns or []),
            conversation_id=row.conversation_id,
        )

    def upsert(
        self,
        record: FindingRecord,
        *,
        campaign_id: str | None = None,
        embedding: list[float] | None = None,
    ) -> FindingRecord:
        """Insert a finding, or merge a repeat sighting into the existing one.

        A repeat appends the campaign to ``seen_in_campaigns`` and can only raise
        severity; status is never changed here (use ``transition``). Existing rows
        are locked (``FOR UPDATE`` on Postgres); a concurrent first insert that loses
        the race is retried as an update."""
        for attempt in (0, 1):
            try:
                return self._upsert_once(record, campaign_id, embedding)
            except IntegrityError:
                if attempt:
                    raise
        raise AssertionError("unreachable")  # pragma: no cover

    def _upsert_once(
        self, record: FindingRecord, campaign_id: str | None, embedding: list[float] | None
    ) -> FindingRecord:
        with session_scope(self._factory) as s:
            row = s.get(orm.FindingRow, record.finding_id, with_for_update=True)
            if row is None:
                row = orm.FindingRow(
                    finding_id=record.finding_id,
                    target_id=record.target_id,
                    component=record.component,
                    technique=record.technique,
                    asi_class=record.asi_class,
                    severity=record.severity,
                    status="open",
                    title=record.title,
                    first_seen_campaign=campaign_id or record.first_seen_campaign,
                    last_seen_campaign=campaign_id or record.last_seen_campaign,
                    seen_in_campaigns=[campaign_id] if campaign_id else [],
                    conversation_id=record.conversation_id,
                    embedding=embedding,
                )
                s.add(row)
                s.flush()
                s.add(
                    orm.FindingEventRow(
                        finding_id=row.finding_id, from_status=None, to_status="open",
                        reviewer_id="system", rationale="finding created",
                    )
                )
            else:
                if campaign_id:
                    seen = list(row.seen_in_campaigns or [])
                    if campaign_id not in seen:
                        seen.append(campaign_id)
                    row.seen_in_campaigns = seen
                    row.last_seen_campaign = campaign_id
                if _SEVERITY_ORDER.index(record.severity) > _SEVERITY_ORDER.index(row.severity):
                    row.severity = record.severity
                if embedding is not None and row.embedding is None:
                    row.embedding = embedding
            s.flush()
            return self._rec(row)

    def get(self, finding_id: str) -> FindingRecord | None:
        with session_scope(self._factory) as s:
            row = s.get(orm.FindingRow, finding_id)
            return self._rec(row) if row else None

    def list(self, target_id: str | None = None, status: FindingStatus | None = None) -> list[FindingRecord]:
        with session_scope(self._factory) as s:
            q = select(orm.FindingRow).order_by(orm.FindingRow.created_at)
            if target_id:
                q = q.where(orm.FindingRow.target_id == target_id)
            if status:
                q = q.where(orm.FindingRow.status == status)
            return [self._rec(r) for r in s.scalars(q)]

    def transition(
        self,
        finding_id: str,
        new_status: FindingStatus,
        *,
        reviewer_id: str | None = None,
        rationale: str | None = None,
    ) -> FindingRecord:
        """Move a finding along the lifecycle, storing who and why, plus an audit row.

        Terminal targets (wont_fix, false_positive) require reviewer and rationale."""
        if new_status not in FINDING_TRANSITIONS:
            raise InvalidTransition(f"unknown status {new_status!r}")
        reviewer = (reviewer_id or "").strip() or None
        why = redact((rationale or "").strip()).text or None
        if new_status in TERMINAL_FINDING_STATUSES and not (reviewer and why):
            raise InvalidTransition(f"{new_status} requires reviewer_id and rationale")
        with session_scope(self._factory) as s:
            row = s.get(orm.FindingRow, finding_id, with_for_update=True)
            if row is None:
                raise KeyError(finding_id)
            old = row.status
            if new_status not in FINDING_TRANSITIONS.get(old, frozenset()):
                raise InvalidTransition(f"cannot move finding from {old} to {new_status}")
            row.status = new_status
            s.add(
                orm.FindingEventRow(
                    finding_id=finding_id, from_status=old, to_status=new_status,
                    reviewer_id=reviewer, rationale=why,
                )
            )
            s.add(
                _audit_row(
                    reviewer or "unknown",
                    "finding.transition",
                    f"finding:{finding_id}",
                    {"from": old, "to": new_status, "rationale": why},
                )
            )
            s.flush()
            return self._rec(row)

    def events(self, finding_id: str) -> list[FindingEvent]:
        with session_scope(self._factory) as s:
            rows = s.scalars(
                select(orm.FindingEventRow)
                .where(orm.FindingEventRow.finding_id == finding_id)
                .order_by(orm.FindingEventRow.id)
            ).all()
            return [
                FindingEvent(
                    finding_id=r.finding_id, from_status=r.from_status, to_status=r.to_status,
                    reviewer_id=r.reviewer_id, rationale=r.rationale, at=r.at,
                )
                for r in rows
            ]

    def find_similar(
        self,
        target_id: str,
        embedding: list[float],
        *,
        threshold: float = DEDUP_THRESHOLD,
        open_only: bool = True,
    ) -> list[tuple[str, float]]:
        """Findings of the same target with cosine similarity >= threshold, best first.

        Uses the pgvector ``<=>`` operator on Postgres and a Python scan on SQLite."""
        with session_scope(self._factory) as s:
            if s.get_bind().dialect.name == "postgresql":
                vec = "[" + ",".join(repr(float(x)) for x in embedding) + "]"
                sql = (
                    "SELECT finding_id, 1 - (embedding <=> CAST(:v AS vector)) AS sim "
                    "FROM findings WHERE target_id = :t AND embedding IS NOT NULL"
                    + (" AND status = 'open'" if open_only else "")
                    + " AND 1 - (embedding <=> CAST(:v AS vector)) >= :th ORDER BY sim DESC"
                )
                rows = s.execute(text(sql), {"v": vec, "t": target_id, "th": threshold}).all()
                return [(r[0], float(r[1])) for r in rows]
            q = select(orm.FindingRow).where(
                orm.FindingRow.target_id == target_id, orm.FindingRow.embedding.is_not(None)
            )
            if open_only:
                q = q.where(orm.FindingRow.status == "open")
            scored = [
                (r.finding_id, _cosine(embedding, list(r.embedding))) for r in s.scalars(q)
            ]
            return sorted(
                [(i, sc) for i, sc in scored if sc >= threshold], key=lambda x: x[1], reverse=True
            )


# ── Audit and budget ─────────────────────────────────────────────────────────


class AuditEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actor: str
    action: str
    object: str
    at: datetime
    details: dict[str, Any]


class AuditRepo:
    def __init__(self, factory: sessionmaker[Session]) -> None:
        self._factory = factory

    def record(
        self, actor: str, action: str, obj: str, details: dict[str, Any] | None = None
    ) -> None:
        """Append an audit row. String values in ``details`` are redacted first."""
        with session_scope(self._factory) as s:
            s.add(_audit_row(actor, action, obj, details))

    def list(self, *, action: str | None = None, obj: str | None = None) -> list[AuditEntry]:
        with session_scope(self._factory) as s:
            q = select(orm.AuditLogRow).order_by(orm.AuditLogRow.id)
            if action:
                q = q.where(orm.AuditLogRow.action == action)
            if obj:
                q = q.where(orm.AuditLogRow.object == obj)
            return [
                AuditEntry(actor=r.actor, action=r.action, object=r.object, at=r.at, details=r.details)
                for r in s.scalars(q)
            ]


class BudgetLedgerRepo:
    def __init__(self, factory: sessionmaker[Session]) -> None:
        self._factory = factory

    def add(self, campaign_id: str, kind: str, amount: float) -> None:
        if kind not in orm.BUDGET_KINDS:
            raise ValueError(f"unknown budget kind {kind!r}")
        if amount < 0:
            raise ValueError("budget amount must be >= 0")
        with session_scope(self._factory) as s:
            s.add(orm.BudgetLedgerRow(campaign_id=campaign_id, kind=kind, amount=amount))

    def total(self, campaign_id: str, kind: str) -> float:
        with session_scope(self._factory) as s:
            value = s.scalar(
                select(func.coalesce(func.sum(orm.BudgetLedgerRow.amount), 0.0)).where(
                    orm.BudgetLedgerRow.campaign_id == campaign_id,
                    orm.BudgetLedgerRow.kind == kind,
                )
            )
            return float(value or 0.0)

    def totals(self, campaign_id: str) -> dict[str, float]:
        return {k: self.total(campaign_id, k) for k in orm.BUDGET_KINDS}
