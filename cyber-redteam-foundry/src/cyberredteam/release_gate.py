"""Release-baseline comparison for the Agent Canary CI product layer."""

from __future__ import annotations

import ipaddress
import re
import socket
import uuid
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import or_, select

from cyberredteam.storage.models import FindingRecord, ProjectRecord, ReleaseRecord, RunRecord


DEFAULT_STRATEGIES = [
    "prompt_injection",
    "indirect_injection",
    "tool_misuse",
    "sensitive_data_exposure",
    "authorization_boundary",
    "retrieval_poisoning",
]
DEFAULT_GATE = {"block_on": ["critical", "high"], "max_new_findings": 0}
_SLUG_RE = re.compile(r"[^a-z0-9]+")


def slugify(name: str) -> str:
    """Return a stable, URL-safe project slug."""
    slug = _SLUG_RE.sub("-", name.lower()).strip("-")
    return slug or "project"


def validate_public_http_endpoint(endpoint: str, *, allow_private: bool = False) -> None:
    """Reject malformed and private-network target URLs before verification.

    Canary only probes explicitly registered public preview endpoints. Blocking
    loopback, link-local, RFC1918 and reserved addresses keeps the onboarding
    probe from becoming a server-side request forgery primitive.
    """
    parsed = urlparse(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Endpoint must be an absolute http(s) URL")

    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(parsed.hostname, None)}
    except socket.gaierror as error:
        raise ValueError("Endpoint hostname could not be resolved") from error

    for raw_address in addresses:
        address = ipaddress.ip_address(raw_address)
        if not allow_private and (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
        ):
            raise ValueError("Endpoint must not resolve to a private or reserved address")


def project_payload(project: ProjectRecord) -> dict[str, Any]:
    return {
        "project_id": project.project_id,
        "name": project.name,
        "slug": project.slug,
        "repository": project.repository,
        "environment": project.environment,
        "endpoint": project.endpoint,
        "request_template": project.request_template,
        "response_path": project.response_path,
        "strategies": project.strategies or [],
        "gate": project.gate or DEFAULT_GATE,
        "created_at": project.created_at.isoformat() if project.created_at else None,
        "updated_at": project.updated_at.isoformat() if project.updated_at else None,
    }


def release_payload(release: ReleaseRecord) -> dict[str, Any]:
    return {
        "release_id": release.release_id,
        "project_id": release.project_id,
        "commit_sha": release.commit_sha,
        "ref": release.git_ref,
        "event_name": release.event_name,
        "is_baseline": bool(release.is_baseline),
        "environment": release.environment,
        "run_id": release.run_id,
        "status": release.status,
        "decision": release.decision,
        "baseline_release_id": release.baseline_release_id,
        "finding_ids": release.finding_ids or [],
        "summary": release.summary or {},
        "comparison": release.comparison or {},
        "created_at": release.created_at.isoformat() if release.created_at else None,
        "completed_at": release.completed_at.isoformat() if release.completed_at else None,
    }


def create_project(session, data: dict[str, Any]) -> ProjectRecord:
    slug = slugify(data["name"])
    suffix = 2
    candidate = slug
    while session.scalar(select(ProjectRecord).where(ProjectRecord.slug == candidate)):
        candidate = f"{slug}-{suffix}"
        suffix += 1

    project = ProjectRecord(
        project_id=uuid.uuid4().hex,
        name=data["name"].strip(),
        slug=candidate,
        repository=data.get("repository"),
        environment=data.get("environment") or "preview",
        endpoint=data["endpoint"].strip(),
        request_template=data.get("request_template") or '{"message":"{{PROMPT}}"}',
        response_path=data.get("response_path") or None,
        strategies=data.get("strategies") or list(DEFAULT_STRATEGIES),
        gate={**DEFAULT_GATE, **(data.get("gate") or {})},
    )
    session.add(project)
    session.commit()
    session.refresh(project)
    return project


def upsert_ci_project(session, data: dict[str, Any]) -> ProjectRecord:
    """Create or refresh the CI target contract for a GitHub repository.

    CI never needs a dashboard-created project ID. The repository name is its
    identity and the checked-in canary.yaml is the source of truth on every
    run. Secrets are deliberately not accepted or stored in this model.
    """
    repository = data["repository"].strip().lower()
    project = session.scalar(select(ProjectRecord).where(ProjectRecord.repository == repository))
    if project is None:
        project = create_project(
            session,
            {
                **data,
                "name": data.get("name") or repository,
                "repository": repository,
            },
        )
        return project

    project.name = data.get("name") or repository
    project.environment = data.get("environment") or project.environment
    project.endpoint = data["endpoint"].strip()
    project.request_template = data.get("request_template") or project.request_template
    project.response_path = data.get("response_path") or None
    project.strategies = data.get("strategies") or list(DEFAULT_STRATEGIES)
    project.gate = {**DEFAULT_GATE, **(data.get("gate") or {})}
    session.commit()
    session.refresh(project)
    return project


def latest_completed_release(session, project_id: str) -> ReleaseRecord | None:
    query = (
        select(ReleaseRecord)
        .where(ReleaseRecord.project_id == project_id, ReleaseRecord.status == "completed")
        .order_by(ReleaseRecord.completed_at.desc(), ReleaseRecord.created_at.desc())
    )
    return session.scalar(query)


def latest_safe_baseline(session, project_id: str) -> ReleaseRecord | None:
    """Return only a passing default-branch release, never a PR result."""
    return session.scalar(
        select(ReleaseRecord)
        .where(
            ReleaseRecord.project_id == project_id,
            ReleaseRecord.status == "completed",
            ReleaseRecord.decision == "pass",
            ReleaseRecord.is_baseline == 1,
        )
        .order_by(ReleaseRecord.completed_at.desc(), ReleaseRecord.created_at.desc())
    )


def create_release(
    session,
    project: ProjectRecord,
    commit_sha: str,
    environment: str,
    *,
    git_ref: str | None = None,
    event_name: str | None = None,
) -> ReleaseRecord:
    # Preserve the dashboard/manual release behavior for existing users. CI
    # supplies a git ref and therefore uses the stricter main-only baseline.
    baseline = (
        latest_safe_baseline(session, project.project_id)
        if git_ref is not None
        else latest_completed_release(session, project.project_id)
    )
    release = ReleaseRecord(
        release_id=uuid.uuid4().hex,
        project_id=project.project_id,
        commit_sha=commit_sha,
        git_ref=git_ref,
        event_name=event_name,
        environment=environment,
        status="running",
        baseline_release_id=baseline.release_id if baseline else None,
    )
    session.add(release)
    session.commit()
    session.refresh(release)
    return release


def mark_release_failed(session, release_id: str, message: str) -> None:
    release = session.get(ReleaseRecord, release_id)
    if release is None:
        return
    release.status = "failed"
    release.decision = "block"
    release.summary = {"error": message}
    release.completed_at = datetime.utcnow()
    session.commit()


def finalise_release(session, release_id: str, *, default_branch: str = "main") -> ReleaseRecord:
    """Turn canonical findings from a run into an immutable release decision."""
    release = session.get(ReleaseRecord, release_id)
    if release is None:
        raise ValueError("Release not found")
    if not release.run_id:
        raise ValueError("Release has no linked run")

    run = session.get(RunRecord, release.run_id)
    if run is None or run.status != "completed":
        raise ValueError("Release run has not completed")

    project = session.get(ProjectRecord, release.project_id)
    if project is None:
        raise ValueError("Project not found")

    findings = list(
        session.scalars(
            select(FindingRecord).where(
                or_(FindingRecord.first_seen_run == release.run_id, FindingRecord.last_seen_run == release.run_id)
            )
        )
    )
    finding_ids = sorted({finding.finding_id for finding in findings})
    baseline_ids: set[str] = set()
    if release.baseline_release_id:
        baseline = session.get(ReleaseRecord, release.baseline_release_id)
        baseline_ids = set((baseline.finding_ids if baseline else []) or [])

    has_baseline = bool(release.baseline_release_id)
    new_ids = sorted(set(finding_ids) - baseline_ids) if has_baseline else []
    known_ids = sorted(set(finding_ids) & baseline_ids) if has_baseline else []
    severity_by_id = {finding.finding_id: (finding.severity or "info").lower() for finding in findings}
    new_severities = {severity_by_id[finding_id] for finding_id in new_ids}
    gate = {**DEFAULT_GATE, **(project.gate or {})}
    block_on = {value.lower() for value in gate.get("block_on", [])}
    max_new = int(gate.get("max_new_findings", 0))
    blocked = bool(new_severities & block_on) or len(new_ids) > max_new
    decision = "block" if blocked else ("warn" if new_ids else "pass")

    strategy_coverage = len({finding.strategy for finding in findings if finding.strategy})
    configured_strategies = len(project.strategies or [])
    coverage = round((strategy_coverage / configured_strategies) * 100) if configured_strategies else 0
    severity_counts = {
        severity: sum(1 for finding in findings if (finding.severity or "info").lower() == severity)
        for severity in ("critical", "high", "medium", "low")
    }

    release.status = "completed"
    release.decision = decision
    release.finding_ids = finding_ids
    release.summary = {
        "total_findings": len(finding_ids),
        "coverage": coverage,
        "severity_counts": severity_counts,
        "security_score": max(0, 100 - (severity_counts["critical"] * 35 + severity_counts["high"] * 15 + severity_counts["medium"] * 5)),
    }
    release.comparison = {
        "new_finding_ids": new_ids,
        "known_finding_ids": known_ids,
        "resolved_finding_ids": sorted(baseline_ids - set(finding_ids)),
        "baseline_release_id": release.baseline_release_id,
        "baseline_established": not has_baseline and release.git_ref == default_branch,
        "baseline_missing": not has_baseline,
    }
    # Only a clean default-branch commit can become the next comparison point.
    # A PR can be inspected but may never silently move the security baseline.
    release.is_baseline = int(release.git_ref == default_branch and decision == "pass")
    release.completed_at = datetime.utcnow()
    session.commit()
    session.refresh(release)
    return release
