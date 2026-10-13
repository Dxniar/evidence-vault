"""Bounded diagnostic logging; the case audit remains in the database.

Do not log request bodies, headers, passwords, SQL parameters, or evidence
contents. Redaction is a final precaution, not permission to log secrets.
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import TextIO

from flask import Flask, g, has_request_context

LOG_LEVELS = {name: getattr(logging, name) for name in
              ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")}
_URL = re.compile(r"\b(?:https?|postgres(?:ql)?(?:\+psycopg)?):\/\/[^\s<>\"']+", re.I)
_BEARER = re.compile(r"\bBearer\s+[^\s,;\"']+", re.I)
_SECRET = re.compile(
    r"\b(password|passwd|pwd|token|access_token|id_token|refresh_token|"
    r"client_secret|api_key|secret|authorization)\b\s*[=:]\s*"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)", re.I)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")


def redact_diagnostic_message(message: str) -> str:
    """Suppress common credential forms and keep one bounded JSON record."""
    message = _URL.sub("[REDACTED_URL]", message)
    message = _BEARER.sub("Bearer [REDACTED]", message)
    message = _SECRET.sub(lambda match: match.group(1) + "=[REDACTED]", message)
    message = _JWT.sub("[REDACTED_TOKEN]", message)
    return message[:2048]


class SafeJsonFormatter(logging.Formatter):
    """Only explicitly selected fields reach container logs.

    Exception values, SQL statement parameters, stack traces, request headers
    and arbitrary ``extra`` fields are deliberately excluded.
    """
    def format(self, record: logging.LogRecord) -> str:
        args = record.args
        if isinstance(args, dict):
            args = {key: type(value).__name__ if isinstance(value, BaseException) else value
                    for key, value in args.items()}
        elif args:
            args = tuple(type(value).__name__ if isinstance(value, BaseException) else value for value in args)
        if isinstance(record.msg, BaseException):
            message = type(record.msg).__name__
        else:
            message = str(record.msg) % args if args else str(record.msg)
        data = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(
                timespec="milliseconds").replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_diagnostic_message(message),
        }
        request_id = getattr(g, "request_id", None) if has_request_context() else None
        if isinstance(request_id, str) and re.fullmatch(r"[a-f0-9]{16}", request_id):
            data["request_id"] = request_id
        if record.exc_info and record.exc_info[0] is not None:
            data["exception_type"] = record.exc_info[0].__name__
        return json.dumps(data, ensure_ascii=False, separators=(",", ":"))


def configure_application_logging(app: Flask, *, stream: TextIO | None = None) -> None:
    """Configure the app logger once; never reconfigure other applications."""
    name = str(app.config.get("APP_LOG_LEVEL", "INFO")).strip().upper()
    if name not in LOG_LEVELS:
        raise ValueError("APP_LOG_LEVEL: ожидается DEBUG, INFO, WARNING, ERROR или CRITICAL.")
    logger = app.logger
    # Flask logger instances are shared by app.name; replace the existing app
    # handlers so repeated factories cannot duplicate records or bypass safety.
    for old in tuple(logger.handlers):
        logger.removeHandler(old)
        if getattr(old, "_evidence_managed", False):
            old.close()
    handler = logging.StreamHandler(stream)
    handler._evidence_managed = True
    handler.setFormatter(SafeJsonFormatter())
    logger.addHandler(handler)
    logger.setLevel(LOG_LEVELS[name])
    logger.propagate = False
