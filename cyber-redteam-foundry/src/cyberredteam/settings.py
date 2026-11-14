"""Settings and configuration management."""

from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from pydantic import SecretStr
from pydantic_settings import BaseSettings

# Load .env into the process environment so that code reading os.environ
# directly (e.g. the per-role BACKBOARD_<ROLE>_PROVIDER / _MODEL_NAME overrides
# in llm/factory.py) sees values placed in .env. override=False keeps anything
# already exported in the shell authoritative.
load_dotenv(override=False)


class Settings(BaseSettings):
    """Application settings from environment variables."""

    # Backboard.io (LLM gateway). Required; the factory fails closed without it.
    backboard_api_key: Optional[str] = None
    backboard_base_url: str = "https://app.backboard.io/api"
    backboard_timeout_seconds: float = 60.0
    # Fallbacks when a role has no entry in configs/models.yaml.
    backboard_llm_provider: str = "openai"
    backboard_model_name: str = "gpt-4o"

    # API authentication — bearer token required on every API request.
    # Must match the VITE_API_TOKEN configured in the frontend.
    api_secret_key: Optional[str] = None

    # Authorization scope: comma-separated list of target_ids a run may be
    # created against. When set, a run targeting anything else is rejected —
    # "attack only what you're allowed to" as a hard constraint. When empty,
    # no allowlist is enforced (a warning is logged; do not rely on this in
    # production).
    allowed_targets: str = ""
    require_target_allowlist: bool = False

    # Target
    target_mode: str = "http"
    target_endpoint: Optional[str] = None
    target_api_key: Optional[str] = None

    # Logging
    log_level: str = "INFO"
    log_file: Path = Path("runs/cyber_redteam.log")

    # Database
    db_path: Path = Path("runs/redteam.db")
    # v2 data layer (WP6). SQLAlchemy URL, e.g.
    # postgresql+psycopg://canary:canary@localhost:55432/canary
    # Unset → v2 storage uses sqlite:///runs/canary_v2.db (dev/tests only).
    database_url: Optional[str] = None

    # Encryption at rest for target secrets (WP1) and evidence (WP6).
    # A urlsafe-base64 Fernet key; required (fail closed) for any code path
    # that stores secrets or evidence.
    canary_encryption_key: Optional[str] = None
    # Evidence retention in days (WP6 purge job).
    evidence_retention_days: int = 30

    # Report
    report_output_dir: Path = Path("reports")
    report_format: str = "markdown"  # markdown | json | both

    # Run Configuration
    # Total attempts per LLM call (including the first), not retries-after-first.
    # Applied via LangChain's Runnable.with_retry() in the LLM wrapper.
    max_retries: int = 3
    max_concurrent_runs: int = 3
    timeout_seconds: int = 30
    deterministic_seed: int = 42

    # Observability on Weights & Biases (WP11). All optional; no key = no-op.
    wandb_api_key: Optional[SecretStr] = None
    wandb_entity: Optional[str] = None
    wandb_project: str = "canary"
    wandb_mode: str = "online"  # online | offline | disabled
    wandb_export_raw_evidence: bool = False  # raw text only if also environment=staging
    # Global PLATFORM ops webhook (kill switch, Backboard error rate, budget overrun).
    # Per-target on-call is WP3 EngineDeps.on_call / the WP8 target webhook field.
    canary_ops_webhook_url: Optional[str] = None

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
        extra = "ignore"  # tolerate unrelated/legacy env vars


def get_settings() -> Settings:
    """Get application settings singleton."""
    return Settings()
