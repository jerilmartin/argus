"""ARGUS Logging Configuration.

Provides a consistent logging setup across all ARGUS modules.
Uses Python's built-in logging module with configurable log levels.

Never logs passwords, secrets, or sensitive configuration values.
"""

from __future__ import annotations

import logging
import os
import sys

from dotenv import load_dotenv

load_dotenv()


def setup_logging(
    level: str | None = None,
    log_format: str | None = None,
) -> None:
    """Configure logging for the ARGUS application.

    Args:
        level: Log level string (DEBUG, INFO, WARNING, ERROR).
               Defaults to LOG_LEVEL env var, then INFO.
        log_format: Custom format string. Uses a sensible default if not provided.
    """
    if level is None:
        level = os.getenv("LOG_LEVEL", "INFO").upper()

    if log_format is None:
        log_format = (
            "%(asctime)s | %(levelname)-8s | %(name)-30s | %(message)s"
        )

    numeric_level = getattr(logging, level, logging.INFO)

    # Configure the root argus logger
    argus_logger = logging.getLogger("argus")
    argus_logger.setLevel(numeric_level)

    # Avoid adding duplicate handlers on repeated calls
    if not argus_logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(numeric_level)
        formatter = logging.Formatter(log_format, datefmt="%Y-%m-%d %H:%M:%S")
        handler.setFormatter(formatter)
        argus_logger.addHandler(handler)

    # Reduce noise from libraries
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

    argus_logger.info("ARGUS logging initialized at level %s", level)
