"""Structured logging shared by the API and the worker: one JSON object per
line on stdout, which Cloud Logging and Azure Log Analytics both parse. Extra
fields passed via `logger.warning(..., extra={...})` are merged in; the request
id and actor are read from request_ctx at format time.

`severity` duplicates `level` under the key Cloud Logging reads to set the
entry's level, so a CRITICAL line is a CRITICAL entry rather than a DEFAULT one.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone

from . import request_ctx


class JsonFormatter(logging.Formatter):
    _SKIP = frozenset(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {"message", "asctime", "taskName"}

    def format(self, record: logging.LogRecord) -> str:
        payload: dict = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "severity": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        rid = request_ctx.request_id()
        if rid:
            payload["request_id"] = rid
        actor = request_ctx.current()
        payload["role"] = actor.role
        if actor.email:
            payload["actor"] = actor.email
        payload.update({k: v for k, v in record.__dict__.items() if k not in self._SKIP})
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure(name: str = "npr.api") -> logging.Logger:
    """Attach the JSON handler to `name` once (idempotent: uvicorn reloads
    re-import the app) and stop propagation so lines are not printed twice."""
    log = logging.getLogger(name)
    if not log.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
        log.addHandler(handler)
        log.propagate = False
    log.setLevel(os.environ.get("NPR_LOG_LEVEL", "INFO").upper())
    return log
