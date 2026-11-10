"""Transport layer: the stateful HTTP client for target agents (WP2)."""

from cyberredteam.transport.rate_limit import InProcessTokenBucket, RateLimiter
from cyberredteam.transport.session_adapter import (
    CAMPAIGN_HEADER,
    SessionAdapter,
    TargetError,
    TargetErrorKind,
    TurnResult,
)

__all__ = [
    "CAMPAIGN_HEADER",
    "InProcessTokenBucket",
    "RateLimiter",
    "SessionAdapter",
    "TargetError",
    "TargetErrorKind",
    "TurnResult",
]
