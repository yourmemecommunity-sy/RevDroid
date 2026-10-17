"""Logging: one readable format for our code; silence androguard's very chatty loguru output."""
from __future__ import annotations

import logging
import sys

from .config import settings


def setup_logging() -> None:
    logging.basicConfig(
        level=settings.log_level.upper(),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        stream=sys.stdout,
        force=True,
    )
    try:  # androguard 4 logs every parsed element at DEBUG through loguru
        from loguru import logger as loguru_logger
        loguru_logger.remove()
        loguru_logger.add(sys.stderr, level="ERROR")
    except ImportError:
        pass
