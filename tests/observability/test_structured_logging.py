"""Unit tests for Structured JSON Logging & Sensitive Data Redaction (Sprint F6A)."""

from __future__ import annotations

import json
import logging
import io

from karsasec.observability.logger import (
    JSONFormatter,
    StructuredLogger,
    redact_sensitive_data,
)
from karsasec.observability.correlation import correlation_scope


class TestSensitiveDataRedaction:
    def test_redact_dict_sensitive_keys(self):
        raw = {
            "task_id": "tsk-100",
            "auth_token": "secret_token_123",
            "password": "super_secret_pass",
            "normal_field": "visible_value",
        }
        cleaned = redact_sensitive_data(raw)
        assert cleaned["task_id"] == "tsk-100"
        assert cleaned["auth_token"] == "[REDACTED]"
        assert cleaned["password"] == "[REDACTED]"
        assert cleaned["normal_field"] == "visible_value"

    def test_redact_string_sensitive_patterns(self):
        raw_msg = "Database connection failed with database_url='postgresql://user:pass@localhost:5432/db'"
        cleaned = redact_sensitive_data(raw_msg)
        assert "pass@localhost" not in cleaned
        assert "[REDACTED]" in cleaned


class TestJSONFormatter:
    def test_json_formatter_fields(self):
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="karsasec.test",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Task transition queued",
            args=(),
            exc_info=None,
        )
        record.event_type = "TASK_QUEUED"
        record.component = "task_engine"
        record.task_id = "tsk-999"
        record.lease_version = 2

        with correlation_scope("corr-abc-123"):
            formatted = formatter.format(record)

        data = json.loads(formatted)
        assert data["level"] == "INFO"
        assert data["event_type"] == "TASK_QUEUED"
        assert data["component"] == "task_engine"
        assert data["task_id"] == "tsk-999"
        assert data["lease_version"] == 2
        assert data["correlation_id"] == "corr-abc-123"
        assert "timestamp" in data


class TestStructuredLogger:
    def test_structured_logger_emits_valid_json(self):
        stream = io.StringIO()
        logger = StructuredLogger("test_logger")
        logger.logger.handlers.clear()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(JSONFormatter())
        logger.logger.addHandler(handler)

        logger.info(
            event_type="WORKER_REGISTERED",
            message="Worker registered successfully",
            component="worker_registry",
            worker_id="worker-node-1",
            auth_token="secret_token_val",  # Must be redacted
        )

        output = stream.getvalue()
        assert len(output.strip()) > 0
        data = json.loads(output)
        assert data["event_type"] == "WORKER_REGISTERED"
        assert data["worker_id"] == "worker-node-1"
        assert data["auth_token"] == "[REDACTED]"
