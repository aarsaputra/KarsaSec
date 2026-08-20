"""MetricsCollector — Thread-Safe Privacy-Guarded Cluster Metrics Engine (Sprint F4).

Tracks cluster-wide metrics:
  - queue_depth
  - active_workers
  - running_tasks
  - completed_tasks
  - failed_tasks
  - retry_count
  - recovery_count

Invariants:
  - R7-R9: Privacy Boundary — no source code, diffs, tokens, credentials, or API keys exposed.
  - Thread Safety: All increment/decrement operations use atomic locking.
"""

from __future__ import annotations

import threading
from typing import Dict, Any


class MetricsCollector:
    """Thread-safe metrics collector for KarsaSec cluster monitoring."""

    FORBIDDEN_HIGH_CARDINALITY_LABELS = {
        "task_id", "receipt_id", "finding_id", "trace_id", "span_id", "user_id", "tenant_id", "request_id", "session_id"
    }

    # Forbidden key names for privacy compliance check
    FORBIDDEN_METRIC_KEYS = {
        "source_code", "unified_diff", "diff", "patch", "token", "credential", "api_key", "secret"
    }

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._queue_depth: int = 0
        self._active_workers: int = 0
        self._running_tasks: int = 0
        self._completed_tasks: int = 0
        self._failed_tasks: int = 0
        self._retry_count: int = 0
        self._recovery_count: int = 0
        self._registered_metrics: Dict[str, list[str]] = {}

    def register_metric(self, name: str, label_names: list[str] | None = None) -> None:
        """Register a new metric definition. Validates label names early at API registration time."""
        with self._lock:
            if label_names:
                self.validate_labels(label_names)
            self._registered_metrics[name] = label_names or []

    @classmethod
    def validate_labels(cls, label_names: list[str] | dict[str, Any]) -> None:
        """Reject forbidden high-cardinality labels at metric registration/ingestion time."""
        keys = label_names.keys() if isinstance(label_names, dict) else label_names
        for label in keys:
            if label.lower() in cls.FORBIDDEN_HIGH_CARDINALITY_LABELS:
                raise ValueError(
                    f"Cardinality Explosion Risk: High-cardinality label '{label}' rejected at metric registration time."
                )

    # ---------------------------------------------------------------------------
    # Setters & Mutators
    # ---------------------------------------------------------------------------

    MAX_METRIC_VALUE = 10_000_000

    def set_queue_depth(self, value: int) -> None:
        with self._lock:
            self._queue_depth = min(self.MAX_METRIC_VALUE, max(0, value))

    def set_active_workers(self, value: int) -> None:
        with self._lock:
            self._active_workers = min(self.MAX_METRIC_VALUE, max(0, value))

    def set_running_tasks(self, value: int) -> None:
        with self._lock:
            self._running_tasks = min(self.MAX_METRIC_VALUE, max(0, value))

    def inc_completed_tasks(self, count: int = 1) -> None:
        with self._lock:
            self._completed_tasks += max(0, count)

    def inc_failed_tasks(self, count: int = 1) -> None:
        with self._lock:
            self._failed_tasks += max(0, count)

    def inc_retry_count(self, count: int = 1) -> None:
        with self._lock:
            self._retry_count += max(0, count)

    def inc_recovery_count(self, count: int = 1) -> None:
        with self._lock:
            self._recovery_count += max(0, count)

    # ---------------------------------------------------------------------------
    # Getters & Snapshot
    # ---------------------------------------------------------------------------

    @property
    def queue_depth(self) -> int:
        with self._lock:
            return self._queue_depth

    @property
    def active_workers(self) -> int:
        with self._lock:
            return self._active_workers

    @property
    def running_tasks(self) -> int:
        with self._lock:
            return self._running_tasks

    @property
    def completed_tasks(self) -> int:
        with self._lock:
            return self._completed_tasks

    @property
    def failed_tasks(self) -> int:
        with self._lock:
            return self._failed_tasks

    @property
    def retry_count(self) -> int:
        with self._lock:
            return self._retry_count

    @property
    def recovery_count(self) -> int:
        with self._lock:
            return self._recovery_count

    def snapshot(self) -> Dict[str, int]:
        """Return a thread-safe snapshot of all cluster metrics.

        Enforces privacy sanitization check.
        """
        with self._lock:
            metrics = {
                "queue_depth": self._queue_depth,
                "active_workers": self._active_workers,
                "running_tasks": self._running_tasks,
                "completed_tasks": self._completed_tasks,
                "failed_tasks": self._failed_tasks,
                "retry_count": self._retry_count,
                "recovery_count": self._recovery_count,
            }
            # Privacy audit: ensure no forbidden metric keys leak
            for key in metrics:
                if any(forbidden in key.lower() for forbidden in self.FORBIDDEN_METRIC_KEYS):
                    raise ValueError(f"Privacy Boundary Violation: Forbidden key '{key}' in metrics.")
            return metrics
