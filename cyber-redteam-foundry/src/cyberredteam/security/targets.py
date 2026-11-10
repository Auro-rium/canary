"""Registered-target storage.

``TargetStore`` is the interface the API depends on. ``InMemoryTargetStore`` is
the default (single process, lost on restart); WP6 adds a SQL implementation
with the same method names and signatures.

Contract for every implementation:

* ``create`` always stores the target **unverified**, whatever ``config.verified``
  says. Only ``set_verified`` (called after a successful ownership check) flips it.
* Secret auth fields are encrypted at rest with :mod:`cyberredteam.security.crypto`
  (fail closed when the key is missing) and are decrypted only by ``get``/``list``.
* Only the verification token's hash is stored, never the token.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable

from pydantic import SecretStr

from cyberredteam.contracts import TargetConfig
from cyberredteam.security import crypto


@runtime_checkable
class TargetStore(Protocol):
    def create(self, config: TargetConfig) -> str: ...

    def get(self, target_id: str) -> TargetConfig | None: ...

    def list(self) -> list[TargetConfig]: ...

    def set_verified(self, target_id: str, method: str) -> None: ...

    def set_verification_token_hash(self, target_id: str, token_hash: str) -> None: ...

    def get_verification_token_hash(self, target_id: str) -> str | None: ...

    # Added for the auth-URL host binding (WP2 review): extra hosts, beyond the
    # endpoint's registrable domain, that may receive token_url/login_url traffic.
    def set_allowed_auth_hosts(self, target_id: str, hosts: list[str]) -> None: ...

    def get_allowed_auth_hosts(self, target_id: str) -> list[str]: ...


def split_auth_secrets(config: TargetConfig) -> tuple[dict[str, Any], dict[str, str]]:
    """Split ``config.auth`` into (non-secret fields as JSON, plaintext secrets)."""
    auth = config.auth
    secret_fields = {
        name for name in type(auth).model_fields if isinstance(getattr(auth, name), SecretStr)
    }
    plain = auth.model_dump(mode="json", exclude=secret_fields)
    secrets_ = {name: getattr(auth, name).get_secret_value() for name in secret_fields}
    return plain, secrets_


@dataclass
class _Record:
    public: dict[str, Any]
    auth_plain: dict[str, Any]
    auth_secrets_enc: dict[str, str]
    verified: bool = False
    verified_method: str | None = None
    verified_at: datetime | None = None
    token_hash: str | None = None
    allowed_auth_hosts: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class InMemoryTargetStore:
    """Process-local ``TargetStore``; secrets are held only as Fernet ciphertext."""

    def __init__(self, encryption_key: str | None = None) -> None:
        # None → read CANARY_ENCRYPTION_KEY from settings on each use.
        self._key = encryption_key
        self._records: dict[str, _Record] = {}
        self._lock = threading.Lock()

    def create(self, config: TargetConfig) -> str:
        plain, secrets_ = split_auth_secrets(config)
        encrypted = {name: crypto.encrypt_str(value, self._key) for name, value in secrets_.items()}
        record = _Record(
            public=config.model_dump(mode="json", exclude={"auth", "verified"}),
            auth_plain=plain,
            auth_secrets_enc=encrypted,
        )
        with self._lock:
            if config.target_id in self._records:
                raise ValueError(f"target {config.target_id} already exists")
            self._records[config.target_id] = record
        return config.target_id

    def _rebuild(self, record: _Record) -> TargetConfig:
        auth = dict(record.auth_plain)
        for name, ciphertext in record.auth_secrets_enc.items():
            auth[name] = crypto.decrypt_str(ciphertext, self._key)
        return TargetConfig.model_validate(
            {**record.public, "auth": auth, "verified": record.verified}
        )

    def get(self, target_id: str) -> TargetConfig | None:
        with self._lock:
            record = self._records.get(target_id)
        return self._rebuild(record) if record else None

    def list(self) -> list[TargetConfig]:
        with self._lock:
            records = list(self._records.values())
        return [self._rebuild(r) for r in records]

    def set_verified(self, target_id: str, method: str) -> None:
        with self._lock:
            record = self._records.get(target_id)
            if record is None:
                raise KeyError(target_id)
            record.verified = True
            record.verified_method = method
            record.verified_at = datetime.now(timezone.utc)

    def set_verification_token_hash(self, target_id: str, token_hash: str) -> None:
        with self._lock:
            record = self._records.get(target_id)
            if record is None:
                raise KeyError(target_id)
            record.token_hash = token_hash

    def get_verification_token_hash(self, target_id: str) -> str | None:
        with self._lock:
            record = self._records.get(target_id)
            return record.token_hash if record else None

    def set_allowed_auth_hosts(self, target_id: str, hosts: list[str]) -> None:
        with self._lock:
            record = self._records.get(target_id)
            if record is None:
                raise KeyError(target_id)
            record.allowed_auth_hosts = sorted({h.strip().lower() for h in hosts if h.strip()})

    def get_allowed_auth_hosts(self, target_id: str) -> list[str]:
        with self._lock:
            record = self._records.get(target_id)
            return list(record.allowed_auth_hosts) if record else []
