"""Logging that a log aggregator can read.

Human-readable lines on a laptop, one JSON object per line in a deployment.
The switch is `BISHOP_JSON_LOGS`, because the two audiences are different: a
person watching a terminal wants prose, and Datadog, CloudWatch or Loki want
fields they can filter on without a regex.

**The rule this module enforces:** no alert content is ever logged. Bishop's
inputs are attacker-controlled by construction — command lines, hostnames,
email subjects — and a log line is a place where that text escapes the
quarantine boundary that the rest of the system maintains. It would land in an
aggregator that renders it, gets read by an engineer, and in the worst case is
itself parsed by something. So the access log carries identifiers, not content:
a run id, a request id, a status, a duration.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

__all__ = ["configure_logging"]

_STANDARD = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "module",
        "msecs",
        "message",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "thread",
        "threadName",
        "taskName",
    }
)


class JsonFormatter(logging.Formatter):
    """One JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _STANDARD and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            exc_type, exc_value, _ = record.exc_info
            payload["error"] = f"{getattr(exc_type, '__name__', exc_type)}: {exc_value}"
            payload["where"] = f"{record.pathname}:{record.lineno}"
        return json.dumps(payload, default=str)


class HumanFormatter(logging.Formatter):
    """Readable in a terminal, with `extra` fields appended compactly."""

    def format(self, record: logging.LogRecord) -> str:
        base = f"{record.levelname:<7} {record.name:<22} {record.getMessage()}"
        extras = {
            k: v
            for k, v in record.__dict__.items()
            if k not in _STANDARD and not k.startswith("_") and v is not None
        }
        if extras:
            base += "  " + " ".join(f"{k}={v}" for k, v in extras.items())
        if record.exc_info:
            exc_type, exc_value, _ = record.exc_info
            base += f"\n        {getattr(exc_type, '__name__', exc_type)}: {exc_value}"
        return base


def configure_logging(*, json_logs: bool = False, level: str = "INFO") -> None:
    """Install the formatter. Idempotent — safe to call from several entry points."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter() if json_logs else HumanFormatter())

    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level.upper())

    logging.getLogger("uvicorn.access").handlers = []
    logging.getLogger("uvicorn.access").propagate = False
    logging.getLogger("uvicorn.error").handlers = []
    logging.getLogger("uvicorn.error").propagate = True
