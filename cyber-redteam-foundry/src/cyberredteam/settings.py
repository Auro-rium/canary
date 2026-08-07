"""Settings and configuration management."""

from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from pydantic_settings import BaseSettings

# Load .env into the process environment so that libraries reading os.environ
# directly — notably boto3's credential chain (AWS_ACCESS_KEY_ID, etc.) — pick
# up values placed in .env. pydantic-settings reads .env for its own fields,
# but does NOT export to os.environ; without this, AWS creds in .env are
# ignored and boto3 falls back to the default ~/.aws profile. override=False
# keeps any credentials already exported in the shell authoritative.
load_dotenv(override=False)


class Settings(BaseSettings):
    """Application settings from environment variables."""

    # AWS Bedrock
    # Credentials are resolved by the standard boto3 chain (env vars,
    # shared config/credentials file, or instance/role profile). Only the
    # region is read explicitly here; least-privilege IAM should grant
    # bedrock:InvokeModel on the configured model/inference-profile ARNs.
    aws_region: Optional[str] = None

    # API authentication — bearer token required on every API request.
    # Must match the VITE_API_TOKEN configured in the frontend.
    api_secret_key: Optional[str] = None

    # Comma-separated public dashboard origins. Keep this explicit in hosted
    # deployments so the browser API is not open to arbitrary web origins.
    frontend_origins: str = ""

    # Authorization scope: comma-separated list of target_ids a run may be
    # created against. When set, a run targeting anything else is rejected —
    # "attack only what you're allowed to" as a hard constraint. When empty,
    # no allowlist is enforced (a warning is logged; do not rely on this in
    # production).
    allowed_targets: str = ""

    # Target
    target_mode: str = "sandbox"  # sandbox | http
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
    # Applied via LangChain's Runnable.with_retry() in llm/bedrock.py.
    max_retries: int = 3
    max_concurrent_runs: int = 3
    timeout_seconds: int = 30
    deterministic_seed: int = 42

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
        extra = "ignore"  # tolerate leftover AWS_*/legacy env vars


def get_settings() -> Settings:
    """Get application settings singleton."""
    return Settings()
