"""Small, dependency-free security primitives used at trust boundaries.

This package intentionally contains no networking code.  Callers must validate
the URL before DNS lookup and validate every resolved address immediately before
opening a connection.
"""

from .target import (
    TargetValidationError,
    ValidatedTarget,
    validate_resolved_addresses,
    validate_target_url,
)
from .tokens import (
    IssuedProjectToken,
    hash_project_token,
    hash_verification_token,
    issue_project_token,
    issue_verification_token,
    parse_project_token,
    verify_project_token,
    verify_verification_token,
)

__all__ = [
    "IssuedProjectToken",
    "TargetValidationError",
    "ValidatedTarget",
    "hash_project_token",
    "hash_verification_token",
    "issue_project_token",
    "issue_verification_token",
    "parse_project_token",
    "validate_resolved_addresses",
    "validate_target_url",
    "verify_project_token",
    "verify_verification_token",
]
