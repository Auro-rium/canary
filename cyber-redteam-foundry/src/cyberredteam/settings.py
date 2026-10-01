"""Settings and configuration management."""

from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from pydantic_settings import BaseSettings

# override=False keeps any value already exported in the shell authoritative.
load_dotenv(override=False)


class Settings(BaseSettings):
    """Application settings from environment variables."""

    # Backboard.io — provider and model are selected per request; per-agent
    # overrides live in configs/models.yaml.
    backboard_api_key: Optional[str] = None
    backboard_base_url: str = "https://app.backboard.io/api"
    backboard_llm_provider: str = "openai"
    backboard_model_name: str = "gpt-4o"
    backboard_timeout_seconds: float = 60.0

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

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
        extra = "ignore"  # tolerate unrelated env vars


def get_settings() -> Settings:
    """Get application settings singleton."""
    return Settings()
