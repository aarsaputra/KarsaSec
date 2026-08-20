"""Structured JSON Logger for Sprint F6.

Emits JSON-formatted log messages containing mandatory context fields while enforcing
automatic redaction of sensitive credential fields (INV-F5 & F6 rules).
"""

from __future__ import annotations

import datetime
import json
import logging
import re
import sys
from typing import Any

from karsasec.observability.correlation import (
    get_correlation_id,
    get_operation_id,
    get_request_id,
)

SENSITIVE_KEYS = {
    "auth_token",
    "auth_token_hash",
    "secret",
    "password",
    "jwt",
    "api_key",
    "database_url",
    "token",
}

# Regex pattern matching sensitive key-value pairs or URLs in raw text
SENSITIVE_REGEX = re.compile(
    r"(?i)(auth_token|secret|password|jwt|api_key|token|database_url)\s*[:=]\s*['\"]?([^\s'\";,]+)['\"]?"
)


def redact_sensitive_data(val: Any) -> Any:
    """Recursively redacts sensitive values from dictionaries, lists, and strings."""
    if isinstance(val, dict):
        cleaned = {}
        for k, v in val.items():
            if str(k).lower() in SENSITIVE_KEYS:
                cleaned[k] = "[REDACTED]"
            else:
                cleaned[k] = redact_sensitive_data(v)
        return cleaned
    elif isinstance(val, list):
        return [redact_sensitive_data(item) for item in val]
    elif isinstance(val, str):
        return SENSITIVE_REGEX.sub(r"\1=[REDACTED]", val)
    return val


class JSONFormatter(logging.Formatter):
    """Custom JSON log formatter adhering to F6 structured logging specifications."""

    def format(self, record: logging.LogRecord) -> str:
        log_payload: dict[str, Any] = {
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "level": record.levelname,
            "event_type": getattr(record, "event_type", "GENERIC_LOG"),
            "component": getattr(record, "component", record.name),
            "message": record.getMessage(),
            "task_id": getattr(record, "task_id", None),
            "worker_id": getattr(record, "worker_id", None),
            "lease_id": getattr(record, "lease_id", None),
            "fencing_token": getattr(record, "fencing_token", None),
            "lease_version": getattr(record, "lease_version", None),
            "correlation_id": getattr(record, "correlation_id", get_correlation_id()),
            "request_id": getattr(record, "request_id", get_request_id()),
            "operation_id": getattr(record, "operation_id", get_operation_id()),
        }

        # Include additional extra fields
        if hasattr(record, "extra_fields") and isinstance(record.extra_fields, dict):
            for k, v in record.extra_fields.items():
                if k not in log_payload:
                    log_payload[k] = v

        # Apply redaction
        clean_payload = redact_sensitive_data(log_payload)
        return json.dumps(clean_payload)


class StructuredLogger:
    """High-performance wrapper over python logging with structured field binding."""

    def __init__(self, name: str = "karsasec") -> None:
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(JSONFormatter())
            self.logger.addHandler(handler)

    def log_event(
        self,
        level: int,
        event_type: str,
        message: str,
        component: str = "core",
        task_id: str | None = None,
        worker_id: str | None = None,
        lease_id: str | None = None,
        fencing_token: int | None = None,
        lease_version: int | None = None,
        **extra: Any,
    ) -> None:
        """Emits structured JSON log event."""
        extra_dict = {
            "event_type": event_type,
            "component": component,
            "task_id": task_id,
            "worker_id": worker_id,
            "lease_id": lease_id,
            "fencing_token": fencing_token,
            "lease_version": lease_version,
            "extra_fields": extra,
        }
        self.logger.log(level, message, extra=extra_dict)

    def info(self, event_type: str, message: str, **kwargs: Any) -> None:
        self.log_event(logging.INFO, event_type, message, **kwargs)

    def warning(self, event_type: str, message: str, **kwargs: Any) -> None:
        self.log_event(logging.WARNING, event_type, message, **kwargs)

    def error(self, event_type: str, message: str, **kwargs: Any) -> None:
        self.log_event(logging.ERROR, event_type, message, **kwargs)

    def debug(self, event_type: str, message: str, **kwargs: Any) -> None:
        self.log_event(logging.DEBUG, event_type, message, **kwargs)


# Global default logger instance
default_logger = StructuredLogger("karsasec")


def get_logger(name: str = "karsasec") -> StructuredLogger:
    return StructuredLogger(name)
