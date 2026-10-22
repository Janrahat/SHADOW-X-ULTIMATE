"""Logging setup with automatic credential redaction."""
from __future__ import annotations

import logging
import logging.handlers
import os
from pathlib import Path
from typing import Optional

from core.security import redact_text

_CONFIGURED = False
_LOGGER_NAME = "shadow_x"


class RedactionFilter(logging.Filter):
    """Scrub credentials out of every record before it reaches a handler."""

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: D401
        try:
            record.msg = redact_text(record.getMessage())
            record.args = ()
        except Exception:
            pass
        return True


def setup_logging(
    level: str = "INFO", log_dir: Optional[Path] = None, to_file: bool = True
) -> logging.Logger:
    """Idempotent logger factory used by main.py and the modules."""
    global _CONFIGURED
    logger = logging.getLogger(_LOGGER_NAME)
    numeric = getattr(logging, str(level).upper(), logging.INFO)
    logger.setLevel(numeric)

    if _CONFIGURED:
        for handler in logger.handlers:
            if isinstance(handler, logging.StreamHandler) and not isinstance(
                handler, logging.FileHandler
            ):
                handler.setLevel(numeric)
        return logger

    logger.propagate = False
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s", "%Y-%m-%d %H:%M:%S"
    )

    stream = logging.StreamHandler()
    stream.setLevel(numeric)
    stream.setFormatter(formatter)
    stream.addFilter(RedactionFilter())
    logger.addHandler(stream)

    if to_file and log_dir is not None:
        try:
            Path(log_dir).mkdir(parents=True, exist_ok=True)
            target = Path(log_dir) / "shadow_x.log"
            file_handler = logging.handlers.RotatingFileHandler(
                target, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
            )
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(formatter)
            file_handler.addFilter(RedactionFilter())
            logger.addHandler(file_handler)
        except OSError:
            pass

    _CONFIGURED = True
    return logger


def get_logger(name: str = "core") -> logging.Logger:
    """Child logger such as 'shadow_x.modules.url_analyzer'."""
    if not _CONFIGURED:
        setup_logging(os.environ.get("SHADOW_X_LOG_LEVEL", "INFO"), None, False)
    return logging.getLogger("{}.{}".format(_LOGGER_NAME, name))
