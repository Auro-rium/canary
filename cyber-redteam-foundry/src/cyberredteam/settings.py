"""Settings and configuration management."""

from pathlib import Path
from typing import Optional

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings from environment variables."""

    # Azure Foundry
    azure_project_connection_string: Optional[str] = None
    azure_subscription_id: Optional[str] = None
    azure_resource_group: Optional[str] = None
    azure_project_name: Optional[str] = None
    azure_use_default_credential: bool = True
    azure_tenant_id: Optional[str] = None
    azure_client_id: Optional[str] = None
    azure_client_secret: Optional[str] = None

    # Azure OpenAI
    azure_openai_endpoint: Optional[str] = None
    azure_openai_api_key: Optional[str] = None
    azure_openai_api_version: str = "2024-02-15-preview"
    azure_openai_deployment: Optional[str] = None

    # Target
    target_mode: str = "sandbox"  # sandbox | http | foundry_agent
    target_endpoint: Optional[str] = None
    target_api_key: Optional[str] = None

    # Local Red Teaming
    local_redteam_enabled: bool = False

    # Logging
    log_level: str = "INFO"
    log_file: Path = Path("runs/cyber_redteam.log")

    # Database
    db_path: Path = Path("runs/redteam.db")

    # Report
    report_output_dir: Path = Path("reports")
    report_format: str = "markdown"  # markdown | json | both

    # Run Configuration
    max_retries: int = 3
    timeout_seconds: int = 30
    deterministic_seed: int = 42

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


def get_settings() -> Settings:
    """Get application settings singleton."""
    return Settings()
