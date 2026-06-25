"""AWS Bedrock Cyber Red Team Framework."""

__version__ = "0.1.0"
__author__ = "Cyber Red Team"

from cyberredteam.logging import setup_logging
from cyberredteam.schemas import AttackResult, PatchResult, RunConfig

__all__ = ["RunConfig", "AttackResult", "PatchResult", "setup_logging"]
