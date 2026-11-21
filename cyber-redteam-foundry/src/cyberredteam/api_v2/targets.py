"""/api/v2/targets: CRUD + ownership verification, org-scoped (WP1 routes, WP8 authz).

* Read: ``targets:read`` (viewer+). Create/update/delete/verify: ``targets:write`` (operator+).
* Another org's target is a 404. Secrets are masked in every response; the
  on-call webhook is write-only. Validation errors never echo submitted values.
* SSRF guard: endpoint, ``token_url``/``login_url`` and the webhook must be public
  http(s) (checked on create, on every security-relevant update and at verify).
* Changing the endpoint, the auth type or any non-secret auth field (URLs,
  client id, header name, ...), or ``allowed_auth_hosts`` clears verification.
  Rotating only a secret keeps it.
* ``POST /{id}/test-connection`` sends ONE fixed benign message ("Hello") through
  the real SessionAdapter so an operator can check endpoint, auth, template and
  response path. It may run before the target is verified (that is its purpose);
  it is operator-only, SSRF-guarded, rate limited per target and audited.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.concurrency import run_in_threadpool
from pydantic import SecretStr, TypeAdapter, ValidationError

from cyberredteam.api_v2.deps import get_ownership_options, get_target_store, url_check_options
from cyberredteam.api_v2.schemas import (
    TargetCreate,
    TargetCreated,
    TargetList,
    TargetUpdate,
    TargetUpdated,
    TargetView,
    TestConnectionResult,
    VerifyRequest,
    VerifyResult,
)
from cyberredteam.auth.deps import require
from cyberredteam.auth.principal import TARGETS_READ, TARGETS_WRITE, Principal
from cyberredteam.contracts import TargetAuth, TargetConfig
from cyberredteam.jobs.events import scrub_secrets
from cyberredteam.jobs.runner_wiring import auth_secret_values
from cyberredteam.security.ownership import (
    DNS_TXT_PREFIX,
    VERIFY_HEADER,
    WELL_KNOWN_PATH,
    TargetRefused,
    check_target_url,
    check_target_urls,
    verify_ownership,
)
from cyberredteam.security.tokens import hash_verification_token, issue_verification_token
from cyberredteam.storage.v2.redaction import redact
from cyberredteam.storage.v2.repositories import AuditRepo, SqlTargetStore
from cyberredteam.transport.rate_limit import InProcessTokenBucket
from cyberredteam.transport.session_adapter import SessionAdapter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v2/targets", tags=["targets"])

_AUTH = TypeAdapter(TargetAuth)
_UNAVAILABLE = "Target store is unavailable."


def _validation_422(exc: ValidationError) -> HTTPException:
    return HTTPException(
        status_code=422,
        detail=exc.errors(include_input=False, include_url=False, include_context=False),
    )


def _parse_allowed_auth_hosts(raw: list[str] | None) -> list[str]:
    if not raw:
        return []
    if not all(isinstance(h, str) and h.strip() for h in raw):
        raise HTTPException(status_code=422, detail="allowed_auth_hosts must be a list of hostnames")
    hosts = [h.strip().rstrip(".").lower() for h in raw]
    if any(c in h for h in hosts for c in "/:@ "):
        raise HTTPException(status_code=422, detail="allowed_auth_hosts entries must be bare hostnames")
    return hosts


def target_view(target: TargetConfig, store: SqlTargetStore) -> TargetView:
    """Public view: secrets masked, never the verification token, its hash or the webhook."""
    data = target.model_dump(mode="json")  # SecretStr dumps as "**********"
    meta = store.meta(target.target_id)
    return TargetView(
        **data,
        allowed_auth_hosts=store.get_allowed_auth_hosts(target.target_id),
        verified_method=meta.verified_method if meta else None,
        verified_at=meta.verified_at if meta else None,
        oncall_webhook_configured=bool(meta and meta.has_oncall_webhook),
        created_at=meta.created_at if meta else None,
    )


def _verification_instructions(target: TargetConfig, token: str) -> dict[str, dict[str, str]]:
    host = target.endpoint.host or ""
    origin = f"{target.endpoint.scheme}://{host}"
    default_port = {"http": 80, "https": 443}.get(target.endpoint.scheme)
    if target.endpoint.port and target.endpoint.port != default_port:
        origin += f":{target.endpoint.port}"
    return {
        "http_wellknown": {"url": origin + WELL_KNOWN_PATH, "content": token},
        "dns_txt": {"name": DNS_TXT_PREFIX + host, "type": "TXT", "value": token},
        "response_header": {"header": VERIFY_HEADER, "value": token},
    }


def _get_in_org(store: SqlTargetStore, target_id: str, principal: Principal) -> TargetConfig:
    try:
        target = store.get_in_org(target_id, principal.org_id)
    except RuntimeError:  # secret decryption failed (key missing): fail closed
        raise HTTPException(status_code=503, detail=_UNAVAILABLE) from None
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    return target


async def _check_urls(
    endpoint: str, auth: Any, hosts: list[str], webhook: str | None, opts: dict[str, Any]
) -> None:
    try:
        # DNS resolution is blocking; keep it off the event loop.
        await run_in_threadpool(check_target_urls, endpoint, auth, hosts, **opts)
        if webhook:
            await run_in_threadpool(lambda: check_target_url(webhook, **opts))
    except TargetRefused as exc:
        raise HTTPException(status_code=422, detail=f"target refused: {exc}") from None


@router.post("", status_code=201, response_model=TargetCreated)
async def create_target(
    body: TargetCreate,
    principal: Principal = Depends(require(TARGETS_WRITE)),
    store: SqlTargetStore = Depends(get_target_store),
    ownership_options: dict[str, Any] = Depends(get_ownership_options),
):
    """Register an (unverified) target in the caller's org.

    The plaintext verification token is returned in this response only; just its
    hash is kept."""
    hosts = _parse_allowed_auth_hosts(body.allowed_auth_hosts)
    ignored = {"allowed_auth_hosts", "oncall_webhook_url", "auth", "endpoint", "target_id", "verified"}
    fields = body.model_dump(exclude=ignored)
    try:
        config = TargetConfig(
            target_id=str(uuid.uuid4()), endpoint=body.endpoint, auth=body.auth, **fields
        )
    except ValidationError as exc:
        raise _validation_422(exc) from None
    webhook = str(body.oncall_webhook_url) if body.oncall_webhook_url else None
    await _check_urls(str(config.endpoint), config.auth, hosts, webhook,
                      url_check_options(ownership_options))

    token = issue_verification_token()
    try:
        target_id = store.create(config, org_id=principal.org_id, oncall_webhook=webhook)
    except RuntimeError:
        raise HTTPException(
            status_code=503,
            detail="Target secret storage is unavailable (CANARY_ENCRYPTION_KEY not configured).",
        ) from None
    store.set_verification_token_hash(target_id, hash_verification_token(token))
    store.set_allowed_auth_hosts(target_id, hosts)
    AuditRepo(store.factory).record(principal.actor, "target.create", f"target:{target_id}",
                                     {"environment": config.environment})
    logger.info("[API] registered target %s (unverified)", target_id)
    return TargetCreated(
        target=target_view(config, store),
        verification_token=token,
        verification=_verification_instructions(config, token),
    )


@router.get("", response_model=TargetList)
def list_targets(
    principal: Principal = Depends(require(TARGETS_READ)),
    store: SqlTargetStore = Depends(get_target_store),
):
    try:
        targets = store.list_for_org(principal.org_id)
    except RuntimeError:
        raise HTTPException(status_code=503, detail=_UNAVAILABLE) from None
    return TargetList(items=[target_view(t, store) for t in targets])


@router.get("/{target_id}", response_model=TargetView)
def get_target(
    target_id: str,
    principal: Principal = Depends(require(TARGETS_READ)),
    store: SqlTargetStore = Depends(get_target_store),
):
    return target_view(_get_in_org(store, target_id, principal), store)


def _public_auth(auth: Any) -> dict[str, Any]:
    return auth.model_dump(mode="json")  # secrets masked: equal masks = same public shape


def _merge_auth(current: Any, new: dict[str, Any]) -> Any:
    """Validate a new auth object; with the same ``type``, absent/null secrets keep the stored ones."""
    data = dict(new)
    if data.get("type") == current.type:
        for name, value in current:
            if isinstance(value, SecretStr) and data.get(name) is None:
                data[name] = value
    return _AUTH.validate_python(data)


@router.patch("/{target_id}", response_model=TargetUpdated)
async def update_target(
    target_id: str,
    body: TargetUpdate,
    principal: Principal = Depends(require(TARGETS_WRITE)),
    store: SqlTargetStore = Depends(get_target_store),
    ownership_options: dict[str, Any] = Depends(get_ownership_options),
):
    current = _get_in_org(store, target_id, principal)
    given = body.model_fields_set
    if "environment" in given and body.environment != current.environment:
        raise HTTPException(
            status_code=422,
            detail="environment cannot be changed; register a new target instead",
        )
    data = current.model_dump(exclude={"auth", "verified"})
    simple = given - {"auth", "allowed_auth_hosts", "oncall_webhook_url", "environment"}
    for name in simple:
        value = getattr(body, name)
        if value is None and name in ("name", "endpoint", "session_mode", "streaming", "timeout_s"):
            raise HTTPException(status_code=422, detail=f"{name} cannot be null")
        data[name] = value
    try:
        auth = _merge_auth(current.auth, body.auth) if "auth" in given and body.auth else current.auth
        config = TargetConfig(**data, auth=auth)
    except ValidationError as exc:
        raise _validation_422(exc) from None

    old_hosts = store.get_allowed_auth_hosts(target_id)
    hosts = _parse_allowed_auth_hosts(body.allowed_auth_hosts) if "allowed_auth_hosts" in given else old_hosts
    reset = (
        str(config.endpoint) != str(current.endpoint)
        or _public_auth(config.auth) != _public_auth(current.auth)
        or sorted(set(hosts)) != sorted(set(old_hosts))
    )
    webhook_given = "oncall_webhook_url" in given
    webhook = str(body.oncall_webhook_url) if webhook_given and body.oncall_webhook_url else None
    if reset or webhook:
        await _check_urls(str(config.endpoint), config.auth, hosts, webhook,
                          url_check_options(ownership_options))
    try:
        store.update(config, reset_verification=reset)
    except RuntimeError:
        raise HTTPException(status_code=503, detail=_UNAVAILABLE) from None
    if "allowed_auth_hosts" in given:
        store.set_allowed_auth_hosts(target_id, hosts)
    if webhook_given:
        store.set_oncall_webhook(target_id, webhook)
    AuditRepo(store.factory).record(
        principal.actor, "target.update", f"target:{target_id}",
        {"fields": sorted(given), "verification_reset": reset},
    )
    return TargetUpdated(target=target_view(_get_in_org(store, target_id, principal), store),
                         verification_reset=reset)


@router.delete("/{target_id}")
def delete_target(
    target_id: str,
    principal: Principal = Depends(require(TARGETS_WRITE)),
    store: SqlTargetStore = Depends(get_target_store),
) -> dict[str, str]:
    """Delete a target. One with campaign history is archived instead (hidden from
    the org, unverified, credentials dropped). 409 while a campaign is active."""
    _get_in_org(store, target_id, principal)
    if store.has_campaigns(target_id, active_only=True):
        raise HTTPException(status_code=409, detail="Target has a queued or running campaign")
    status = "deleted"
    try:
        if store.has_campaigns(target_id):
            raise ValueError("has campaigns")
        store.delete(target_id)
    except ValueError:
        store.archive(target_id)
        status = "archived"
    AuditRepo(store.factory).record(principal.actor, f"target.{status}", f"target:{target_id}")
    return {"target_id": target_id, "status": status}


@router.post("/{target_id}/verify", response_model=VerifyResult)
def verify_target(
    target_id: str,
    body: VerifyRequest,
    principal: Principal = Depends(require(TARGETS_WRITE)),
    store: SqlTargetStore = Depends(get_target_store),
    ownership_options: dict[str, Any] = Depends(get_ownership_options),
):
    """Run one ownership check. 200 either way; ``verified`` carries the outcome."""
    target = _get_in_org(store, target_id, principal)
    token_hash = store.get_verification_token_hash(target_id)
    if not token_hash:
        raise HTTPException(status_code=409, detail="No verification token issued for this target")

    try:
        # Re-checked at verify time: DNS may have changed since registration.
        check_target_urls(
            str(target.endpoint), target.auth, store.get_allowed_auth_hosts(target_id),
            **url_check_options(ownership_options),
        )
        result = verify_ownership(str(target.endpoint), token_hash, body.method, **ownership_options)
        verified, reason = result.verified, result.reason
    except TargetRefused as exc:
        verified, reason = False, f"refused: {exc}"

    if verified:
        store.set_verified(target_id, body.method)
        target = _get_in_org(store, target_id, principal)
    AuditRepo(store.factory).record(
        principal.actor, "target.verify", f"target:{target_id}",
        {"method": body.method, "verified": verified},
    )
    logger.info("[API] ownership check target=%s method=%s verified=%s", target_id, body.method, verified)
    return VerifyResult(target=target_view(target, store), verified=verified, method=body.method,
                        reason=reason)


# ── test connection ──────────────────────────────────────────────────────────

# Constant on purpose: nothing about the probe message is user-controlled.
TEST_CONNECTION_MESSAGE = "Hello"
TEST_CONNECTION_MIN_INTERVAL_S = 10.0
TEST_CONNECTION_TIMEOUT_S = 15
TEST_CONNECTION_MAX_REPLY_CHARS = 1000
_probe_lock = threading.Lock()
_last_probe: dict[str, float] = {}  # target_id -> monotonic time of the last accepted probe


def _reserve_probe_slot(target_id: str) -> None:
    """At most one probe per target per 10 s (per API process). 429 otherwise."""
    with _probe_lock:
        now = time.monotonic()
        last = _last_probe.get(target_id)
        if last is not None and now - last < TEST_CONNECTION_MIN_INTERVAL_S:
            wait = max(1, int(TEST_CONNECTION_MIN_INTERVAL_S - (now - last) + 0.999))
            raise HTTPException(
                status_code=429,
                detail="Test connection is limited to one request per 10 seconds per target.",
                headers={"Retry-After": str(wait)},
            )
        _last_probe[target_id] = now
        for tid in [t for t, ts in _last_probe.items() if now - ts > 3600]:
            del _last_probe[tid]


@router.post("/{target_id}/test-connection", response_model=TestConnectionResult)
async def test_connection(
    target_id: str,
    principal: Principal = Depends(require(TARGETS_WRITE)),
    store: SqlTargetStore = Depends(get_target_store),
    ownership_options: dict[str, Any] = Depends(get_ownership_options),
):
    """Send one fixed benign message ("Hello") to the target and report what came back.

    Allowed before verification (it is how an operator checks the wizard settings),
    so it sends exactly one constant, harmless request and nothing user-supplied.
    The endpoint and auth URLs pass the SSRF guard first. The reply is redacted and
    the target's own credentials are masked. Credentials are never returned.
    """
    target = _get_in_org(store, target_id, principal)
    opts = url_check_options(ownership_options)
    try:
        await run_in_threadpool(
            check_target_urls, str(target.endpoint), target.auth,
            store.get_allowed_auth_hosts(target_id), **opts,
        )
    except TargetRefused as exc:
        raise HTTPException(status_code=422, detail=f"target refused: {exc}") from None
    _reserve_probe_slot(target_id)

    secrets = auth_secret_values(target)
    probe = target.model_copy(
        update={"timeout_s": min(target.timeout_s, TEST_CONNECTION_TIMEOUT_S)}
    )
    reply, status, latency, error = "", None, 0.0, None
    started = time.perf_counter()
    try:
        async with SessionAdapter(
            probe,
            campaign_id=f"connection-test:{target_id}",
            rate_limiter=InProcessTokenBucket(rps=1.0),
            transport=ownership_options.get("transport"),
        ) as adapter:
            result = await asyncio.wait_for(
                adapter.send(TEST_CONNECTION_MESSAGE), timeout=TEST_CONNECTION_TIMEOUT_S
            )
        status, latency = result.http_status, result.latency_ms
        if result.error is not None:
            error = result.error.kind.value
        else:
            text = scrub_secrets(redact(result.response_text).text, secrets)
            reply = text[:TEST_CONNECTION_MAX_REPLY_CHARS]
    except asyncio.TimeoutError:
        error, latency = "timeout", (time.perf_counter() - started) * 1000.0
    except Exception as exc:  # noqa: BLE001 - never leak exception text (may hold credentials)
        error, latency = "error", (time.perf_counter() - started) * 1000.0
        logger.warning("[API] test-connection target=%s failed (%s)", target_id, type(exc).__name__)

    parse_ok = error is None
    AuditRepo(store.factory).record(
        principal.actor, "target.test_connection", f"target:{target_id}",
        {"parse_ok": parse_ok, "http_status": status, "error": error,
         "verified": bool(target.verified)},
    )
    logger.info("[API] test-connection target=%s parse_ok=%s status=%s", target_id, parse_ok, status)
    return TestConnectionResult(parse_ok=parse_ok, http_status=status,
                                latency_ms=round(latency, 1), reply=reply, error=error)
