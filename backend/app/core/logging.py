"""Structured logging configuration for SentinelX."""

import logging
import os
import sys


def setup_logging() -> logging.Logger:
    """Configure application-wide structured logger."""
    env_level = os.getenv("LOG_LEVEL", "INFO").upper()
    log_level = getattr(logging, env_level, logging.INFO)

    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    logger = logging.getLogger("sentinelx")
    logger.setLevel(log_level)
    return logger


logger = setup_logging()
