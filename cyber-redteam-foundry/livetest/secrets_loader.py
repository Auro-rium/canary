"""Secrets: loaded by path at run time, held in memory only, never printed.

Values come from the MAIN checkout's .env via ``dotenv_values`` (which does not
touch ``os.environ``) and are handed to subprocesses only through their own
environment dict. ``Secrets`` has no useful repr; reports and logs use names only.
"""

from __future__ import annotations

from pathlib import Path

from dotenv import dotenv_values

MAIN_ENV_PATH = Path.home() / "Documents" / "canary" / "cyber-redteam-foundry" / ".env"
REQUIRED = ("BACKBOARD_API_KEY", "WANDB_API_KEY", "WANDB_ENTITY")
LISTED = (
    "BACKBOARD_API_KEY",
    "WANDB_API_KEY",
    "WANDB_ENTITY",
    "WANDB_PROJECT",
    "CANARY_ENCRYPTION_KEY",
    "BACKBOARD_LLM_PROVIDER",
    "BACKBOARD_MODEL_NAME",
)
SENSITIVE = frozenset({"BACKBOARD_API_KEY", "WANDB_API_KEY", "CANARY_ENCRYPTION_KEY"})


class MissingSecrets(RuntimeError):
    pass


class Secrets:
    def __init__(self, values: dict[str, str]) -> None:
        self._v = {k: v for k, v in values.items() if v}
        self._extra: dict[str, str] = {}

    def __repr__(self) -> str:  # never show values
        return f"Secrets(names={sorted(self._v)})"

    __str__ = __repr__

    @classmethod
    def from_file(cls, path: Path = MAIN_ENV_PATH) -> "Secrets":
        if not path.is_file():
            raise MissingSecrets(f"secrets file not found: {path}")
        raw = dotenv_values(path)
        s = cls({k: (v or "").strip() for k, v in raw.items()})
        s._raw_names = {k: bool((v or "").strip()) for k, v in raw.items()}
        return s

    def get(self, name: str) -> str | None:
        return self._v.get(name) or self._extra.get(name)

    def add_runtime(self, name: str, value: str) -> None:
        """Register a value generated in memory (target keys, fake keys) for the leak sweep."""
        self._extra[name] = value

    def status(self) -> dict[str, str]:
        raw = getattr(self, "_raw_names", {})
        out = {}
        for name in LISTED:
            if name in self._v:
                out[name] = "set"
            elif name in raw:
                out[name] = "empty"
            else:
                out[name] = "absent"
        return out

    def missing_required(self) -> list[str]:
        return [n for n in REQUIRED if not self._v.get(n)]

    def sweep_values(self) -> dict[str, str]:
        """Name -> value pairs to search for. Names are safe to print; values are not."""
        out = {n: v for n, v in self._v.items() if n in SENSITIVE}
        out.update(self._extra)
        return {n: v for n, v in out.items() if len(v) >= 6}

    def scrub(self, text: str) -> str:
        for v in list(self._v.values()) + list(self._extra.values()):
            if len(v) >= 6:
                text = text.replace(v, "[REDACTED]")
        return text
