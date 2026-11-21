"""Roles, permissions and the authenticated principal (WP8).

Roles are hierarchical and org-scoped: ``viewer`` < ``operator`` < ``admin``.
Every principal belongs to exactly one org; every v2 query is filtered by it.
There is no cross-org (platform) role.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Role = Literal["viewer", "operator", "admin"]
AuthMethod = Literal["session", "api_key"]

# Permission names.
TARGETS_READ = "targets:read"
TARGETS_WRITE = "targets:write"
CAMPAIGNS_READ = "campaigns:read"
CAMPAIGNS_LAUNCH = "campaigns:launch"
CAMPAIGNS_CANCEL = "campaigns:cancel"
EVIDENCE_READ = "evidence:read"
EVIDENCE_READ_RAW = "evidence:read_raw"
FINDINGS_READ = "findings:read"
FINDINGS_TRIAGE = "findings:triage"
REPORTS_READ = "reports:read"
KILL_SWITCH_READ = "kill_switch:read"
KILL_SWITCH_WRITE = "kill_switch:write"
LEGACY_READ = "legacy:read"  # deprecated v1 routes (legacy data has no org)

_VIEWER = frozenset(
    {
        TARGETS_READ, CAMPAIGNS_READ, EVIDENCE_READ, FINDINGS_READ, REPORTS_READ,
        KILL_SWITCH_READ,
    }
)
_OPERATOR = _VIEWER | {TARGETS_WRITE, CAMPAIGNS_LAUNCH, CAMPAIGNS_CANCEL, FINDINGS_TRIAGE}
_ADMIN = _OPERATOR | {KILL_SWITCH_WRITE, EVIDENCE_READ_RAW, LEGACY_READ}

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "viewer": _VIEWER,
    "operator": frozenset(_OPERATOR),
    "admin": frozenset(_ADMIN),
}

# Grants that may be given to a user on top of the role (e.g. an operator who
# triages evidence). Anything else in ``users.extra_permissions`` is ignored.
GRANTABLE_PERMISSIONS = frozenset({EVIDENCE_READ_RAW})


def permissions_for(role: str, extra: list[str] | tuple[str, ...] = ()) -> frozenset[str]:
    base = ROLE_PERMISSIONS.get(role)
    if base is None:  # unknown role: nothing (fail closed)
        return frozenset()
    return base | (frozenset(extra) & GRANTABLE_PERMISSIONS)


@dataclass(frozen=True)
class Principal:
    user_id: str
    org_id: str
    role: Role
    auth_method: AuthMethod
    email: str | None = None
    display_name: str = ""
    permissions: frozenset[str] = field(default_factory=frozenset)
    # Session principals only: hash of the CSRF token bound to the session.
    session_hash: str | None = None
    csrf_hash: str | None = None
    api_key_id: str | None = None

    def can(self, permission: str) -> bool:
        return permission in self.permissions

    @property
    def actor(self) -> str:
        """The identity written to audit rows and finding events."""
        return f"user:{self.user_id}"
