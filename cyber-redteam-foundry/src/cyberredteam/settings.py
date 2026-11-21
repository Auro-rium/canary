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

    # API authentication (WP8): OIDC browser sessions or per-user API keys
    # (``cyber-rt auth ...``). There is no shared master token any more; the old
    # API_SECRET_KEY is ignored. Tokens never go into VITE_* variables.

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
    # Local W&B run-file directory (never the CWD). Unset -> <system temp>/canary-wandb.
    wandb_dir: Optional[str] = None
    wandb_export_raw_evidence: bool = False  # raw text only if also environment=staging
    # Global PLATFORM ops webhook (kill switch, Backboard error rate, budget overrun).
    # Per-target on-call is WP3 EngineDeps.on_call / the WP8 target webhook field.
    canary_ops_webhook_url: Optional[str] = None

    # WP7 control plane / jobs. Appended; do not reorder fields above.
    # The global kill switch env var CANARY_KILL_SWITCH is read directly from the
    # process environment by jobs/control.py (any value other than empty/0/false/
    # no/off means ON; it takes effect when the process starts). The live control
    # is the DB flag set by POST /api/v2/admin/kill-switch.
    # Worker heartbeat cadence and the age after which a "running" campaign
    # without a fresh heartbeat is considered orphaned and re-enqueued.
    worker_heartbeat_interval_s: float = 10.0
    worker_stale_after_s: float = 45.0
    # DbRunControl cache TTL. 0 = read the flags uncached before every turn
    # (one PK lookup), which is what guarantees "within one turn".
    run_control_cache_s: float = 0.0
    # SSE event-log poll interval for GET /api/v2/campaigns/{id}/events.
    sse_poll_interval_s: float = 0.5
    # Worker graceful shutdown; must stay below the compose stop_grace_period (40s).
    worker_shutdown_graceful_s: float = 25.0
    # "package.module:callable" returning a PlannerFactory for the worker (WP4 supplies
    # real planners). Unset: the worker fails campaigns closed ("no planner configured").
    planner_factory: Optional[str] = None

    # Turn planners (WP4).
    # Per-message length cap; longer planner output is rejected, not truncated.
    planner_max_message_chars: int = 4000
    # LLMPlanner system prompt (owned by the security owner). Unset means
    # <project>/prompts/planner.md. Missing or empty: LLMPlanner fails closed.
    planner_prompt_path: Optional[Path] = None
    # ScriptedPlanner packs directory. Unset means <project>/packs.
    planner_packs_dir: Optional[Path] = None
    # Estimated USD per 1k planner tokens (Backboard reports tokens, not cost).
    # Deliberately high so the campaign USD budget errs on the safe side.
    planner_usd_per_1k_input_tokens: float = 0.01
    planner_usd_per_1k_output_tokens: float = 0.03
    # How much of each target reply the planner model sees per turn.
    planner_transcript_chars_per_turn: int = 2000

    # WP8 auth. OIDC providers are enabled when both id and secret are set.
    oidc_github_client_id: Optional[str] = None
    oidc_github_client_secret: Optional[SecretStr] = None
    oidc_google_client_id: Optional[str] = None
    oidc_google_client_secret: Optional[SecretStr] = None
    # Public origin of the API as the browser sees it (the Vercel/nginx proxy),
    # used to build the OIDC redirect_uri: <base>/api/v2/auth/callback/<provider>.
    public_base_url: Optional[str] = None
    # Deployment mode. Anything but dev/test is treated as production: OIDC login
    # then needs PUBLIC_BASE_URL (never derived from the Host header) and Secure
    # session cookies.
    canary_env: str = "production"
    # Platform operators (user ids or emails, comma separated). Only they may flip
    # the global kill switch, which halts every org.
    canary_platform_admins: str = ""
    session_ttl_s: int = 12 * 3600
    # Secure cookies need HTTPS; set False only for local http development.
    session_cookie_secure: bool = True
    # Deprecated v1 read routes (/api/runs, /api/findings, ...): kept for one
    # release, admin-only (legacy data has no org). False -> 410 Gone.
    v1_api_enabled: bool = True
    v1_sunset: str = "2027-03-01"

    @property
    def is_dev_or_test(self) -> bool:
        return self.canary_env.strip().lower() in {"dev", "development", "test", "local"}

    @property
    def platform_admin_set(self) -> frozenset[str]:
        return frozenset(p.strip().lower() for p in self.canary_platform_admins.split(",") if p.strip())

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
        extra = "ignore"  # tolerate unrelated/legacy env vars


def get_settings() -> Settings:
    """Get application settings singleton."""
    return Settings()
