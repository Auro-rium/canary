"""Logging configuration."""

import logging
import json
import os
from pathlib import Path
from typing import Optional

from rich.logging import RichHandler


def setup_logging(
    log_level: str = "INFO",
    log_file: Optional[Path] = None,
    name: str = "cyberredteam",
) -> logging.Logger:
    """
    Configure logging with rich handler and optional file output.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional path to log file
        name: Logger name

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, log_level.upper()))

    # Remove existing handlers
    logger.handlers.clear()

    # Console handler with rich formatting
    console_handler = RichHandler(
        rich_tracebacks=True,
        show_time=True,
        show_level=True,
        show_path=False,
    )
    console_handler.setLevel(getattr(logging, log_level.upper()))
    logger.addHandler(console_handler)

    # Default to the configured runtime log path so container logs are also
    # persisted to the mounted runs volume.
    if log_file is None:
        configured = os.getenv("LOG_FILE")
        if configured:
            log_file = Path(configured)

    # File handler if specified
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        file_handler.setFormatter(file_formatter)
        file_handler.setLevel(getattr(logging, log_level.upper()))
        logger.addHandler(file_handler)

    return logger


def log_event(logger: logging.Logger, event: str, **fields: object) -> None:
    """Emit a machine-readable event without logging secrets or bodies."""
    logger.info(json.dumps({"event": event, **fields}, default=str, sort_keys=True))
