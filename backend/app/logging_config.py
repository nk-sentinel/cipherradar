"""Centralized structured logging configuration.

Provides a JSON formatter and single-point setup for the entire backend.
Call ``setup_logging()`` once at application startup (in ``main.py``).

All log records are emitted as single-line JSON objects to stdout, making
them easy to parse by log aggregators (Loki, Datadog, ELK, etc.).
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone


class JSONFormatter(logging.Formatter):
    """Emit each log record as a single-line JSON object.

    Standard fields: ``timestamp``, ``level``, ``logger``, ``message``.
    Extra structured fields can be attached via
    ``extra={"extra_fields": {...}}`` on any log call.
    """

    def format(self, record: logging.LogRecord) -> str:
        log_data: dict = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Merge caller-supplied structured fields
        if hasattr(record, "extra_fields"):
            log_data.update(record.extra_fields)

        # Attach exception info when present
        if record.exc_info and record.exc_info[0]:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data, default=str)


def setup_logging(level: str = "INFO") -> None:
    """Configure the root logger with JSON output to stdout.

    Parameters
    ----------
    level:
        Log level name (DEBUG, INFO, WARNING, ERROR, CRITICAL).
    """
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Quiet noisy third-party loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
