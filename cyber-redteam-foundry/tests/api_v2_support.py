"""Shared harness for the WP8 API v2 tests (not collected by pytest).

``v2`` gives a migrated database (SQLite, or Postgres when configured) with two
orgs, ``a`` and ``b``, and one user per role in each. Requests authenticate for
real: every actor has an API key and a browser session (cookie + CSRF token).
No IdP, DNS or target is contacted: ownership checks use a fake transport and
resolver, the job queue only records enqueues and OIDC uses ``FakeOIDCProvider``.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

import httpx
import pytest
from fastapi.testclient import TestClient
from storage_v2_support import make_policy

from cyberredteam.api import app, require_auth
from cyberredteam.api_v2.auth_routes import CSRF_COOKIE, get_oidc_providers
from cyberredteam.api_v2.deps import get_job_queue, get_ownership_options
from cyberredteam.auth.deps import SESSION_COOKIE, get_db_factory, get_principal
from cyberredteam.auth.oidc import FakeOIDCProvider
from cyberredteam.auth.repo import AuthRepo
from cyberredteam.contracts import (
    BearerAuth,
    CampaignPolicy,
    Conversation,
    ConversationVerdict,
    TargetConfig,
    Turn,
)
from cyberredteam.jobs.queue import InProcessQueue
from cyberredteam.security.ownership import VERIFY_HEADER
from cyberredteam.storage.v2.repositories import (
    CampaignRepo,
    ConversationRepo,
    FindingRecord,
    FindingRepo,
    SqlTargetStore,
    VerdictRepo,
)

ROLES = ("viewer", "operator", "admin")
TARGET_SECRET = "tok-TARGET-secret-9f3a"
ENDPOINT = "https://agent.example.com/v1/chat"


class FakeOwnedTarget:
    """Publishes whatever verification token it is told to, via all three channels."""

    def __init__(self) -> None:
        self.token: str | None = None
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.path == "/.well-known/canary-verify.txt":
            return httpx.Response(200, text=self.token) if self.token else httpx.Response(404)
        headers = {VERIFY_HEADER: self.token} if self.token else {}
        return httpx.Response(200, headers=headers, json={"reply": "hello"})

    def txt(self, name, timeout):
        return [self.token] if self.token and name.startswith("_canary-verify.") else []


@dataclass
class Actor:
    org: str
    role: str
    user_id: str
    org_id: str
    api_key: str
    session: str
    csrf: str

    @property
    def actor(self) -> str:
        return f"user:{self.user_id}"

    def headers(self, mode: str = "api_key") -> dict[str, str]:
        if mode == "api_key":
            return {"Authorization": f"Bearer {self.api_key}"}
        return {"Cookie": f"{SESSION_COOKIE}={self.session}; {CSRF_COOKIE}={self.csrf}",
                "X-CSRF-Token": self.csrf}


@dataclass
class V2Env:
    factory: object
    client: TestClient
    auth: AuthRepo
    orgs: dict[str, str]
    actors: dict[tuple[str, str], Actor]
    owned: FakeOwnedTarget
    queue: InProcessQueue
    oidc: FakeOIDCProvider
    ownership: dict = field(default_factory=dict)

    def actor(self, role: str, org: str = "a") -> Actor:
        return self.actors[(org, role)]

    def h(self, role: str = "admin", org: str = "a", mode: str = "api_key") -> dict[str, str]:
        return self.actor(role, org).headers(mode)

    # ── seeding (directly through the repositories) ──────────────────────────

    def target(self, org: str = "a", *, verified: bool = True, environment: str = "staging",
               secret: str = TARGET_SECRET, webhook: str | None = None) -> str:
        store = SqlTargetStore(self.factory)
        cfg = TargetConfig(
            target_id=str(uuid.uuid4()), name=f"agent-{org}", endpoint=ENDPOINT,
            auth=BearerAuth(token=secret), request_template='{"input": "{{MESSAGE}}"}',
            response_path="reply", session_mode="stateless_history", environment=environment,
        )
        store.create(cfg, org_id=self.orgs[org] if org else None, oncall_webhook=webhook)
        store.set_verification_token_hash(cfg.target_id, "unused-hash")
        if verified:
            store.set_verified(cfg.target_id, "response_header")
        return cfg.target_id

    def campaign(self, target_id: str, *, status: str | None = None,
                 policy: CampaignPolicy | None = None) -> str:
        cid = f"c-{uuid.uuid4().hex[:12]}"
        repo = CampaignRepo(self.factory)
        repo.create(cid, target_id, policy or make_policy(), created_by="seed")
        if status:
            repo.set_status(cid, status)
        return cid

    def conversation(self, campaign_id: str, *, message: str = "hello agent",
                     response: str = "my reply", verdict: str | None = "confirmed",
                     technique: str = "prompt_injection", trial: int = 0) -> str:
        conv_id = f"conv-{uuid.uuid4().hex[:12]}"
        turn = Turn(conversation_id=conv_id, index=0, message=message, response_text=response,
                    latency_ms=5.0)
        ConversationRepo(self.factory).create(
            Conversation(conversation_id=conv_id, campaign_id=campaign_id, technique=technique,
                         trial_index=trial, status="completed", turns=[turn],
                         target_session_ref="sess-REF-123")
        )
        if verdict:
            VerdictRepo(self.factory).save(
                ConversationVerdict(
                    conversation_id=conv_id, verdict=verdict, first_failing_turn=0,
                    deterministic_hits=[], judge_votes=[], judge_agreement=1.0,
                    severity="high", asi_class="ASI01", rationale=f"leaked: {response}",
                )
            )
        return conv_id

    def finding(self, target_id: str, campaign_id: str | None = None,
                conversation_id: str | None = None, severity: str = "high") -> str:
        fid = f"f-{uuid.uuid4().hex[:12]}"
        FindingRepo(self.factory).upsert(
            FindingRecord(finding_id=fid, target_id=target_id, technique="prompt_injection",
                          asi_class="ASI01", severity=severity, title="Prompt injection",
                          conversation_id=conversation_id),
            campaign_id=campaign_id,
        )
        return fid

    def chain(self, org: str = "a") -> dict[str, str]:
        """target -> completed campaign -> conversation (confirmed) -> finding."""
        tid = self.target(org)
        cid = self.campaign(tid, status="completed")
        conv = self.conversation(cid)
        fid = self.finding(tid, cid, conv)
        return {"target_id": tid, "campaign_id": cid, "conversation_id": conv, "finding_id": fid}


@pytest.fixture
def v2(db_factory):
    auth = AuthRepo(db_factory)
    orgs = {"a": auth.create_org("org-a"), "b": auth.create_org("org-b")}
    actors: dict[tuple[str, str], Actor] = {}
    for org, org_id in orgs.items():
        for role in ROLES:
            uid = auth.create_user(org_id, role, email=f"{role}@{org}.example",
                                   display_name=f"{role} {org}")
            _, key = auth.create_api_key(uid, "test")
            session, csrf = auth.create_session(uid, 3600)
            actors[(org, role)] = Actor(org, role, uid, org_id, key, session, csrf)

    owned = FakeOwnedTarget()
    queue = InProcessQueue()
    oidc = FakeOIDCProvider("fake")
    ownership = {
        "allow_private_targets": False,
        "transport": httpx.MockTransport(owned.handler),
        "resolve_host": lambda host: ["93.184.216.34"],
        "txt_resolver": owned.txt,
    }
    saved = dict(app.dependency_overrides)
    app.dependency_overrides.pop(require_auth, None)
    app.dependency_overrides.pop(get_principal, None)
    app.dependency_overrides[get_db_factory] = lambda: db_factory
    app.dependency_overrides[get_ownership_options] = lambda: ownership
    app.dependency_overrides[get_job_queue] = lambda: queue
    app.dependency_overrides[get_oidc_providers] = lambda: {"fake": oidc}
    client = TestClient(app, base_url="https://testserver")
    try:
        yield V2Env(db_factory, client, auth, orgs, actors, owned, queue, oidc, ownership)
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(saved)
