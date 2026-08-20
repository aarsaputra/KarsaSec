"""MetricsRegistry & MetricsCollector — Telemetry Engine (Sprint F6B).

Enforces INV-F6-METRIC-01: No high-cardinality dynamic identifiers (task_id, worker_id,
lease_id, fencing_token, correlation_id, etc.) may appear as Prometheus metric labels.

Guarantees non-blocking metric isolation: metric recording failures never disrupt primary
authoritative state transitions or operations.
"""

from __future__ import annotations

import collections
import contextlib
import threading
import time
from collections.abc import Generator, Mapping, Sequence
from typing import Any

from karsasec.observability.logger import default_logger

# ---------------------------------------------------------------------------
# INV-F6-METRIC-01 Cardinality Policy
# ---------------------------------------------------------------------------

ALLOWED_METRIC_LABELS: frozenset[str] = frozenset(
    {
        "result",
        "state",
        "component",
        "operation",
    }
)

FORBIDDEN_HIGH_CARDINALITY_LABELS: frozenset[str] = frozenset(
    {
        "task_id",
        "worker_id",
        "lease_id",
        "event_id",
        "fencing_token",
        "correlation_id",
        "request_id",
        "operation_id",
        "uuid",
        "receipt_id",
        "finding_id",
        "trace_id",
        "span_id",
        "user_id",
        "tenant_id",
        "session_id",
    }
)

FORBIDDEN_METRIC_KEYS: frozenset[str] = frozenset(
    {
        "source_code",
        "unified_diff",
        "diff",
        "patch",
        "token",
        "credential",
        "api_key",
        "secret",
        "password",
        "jwt",
        "database_url",
    }
)


def validate_metric_labels(labels: Mapping[str, str] | Sequence[str]) -> None:
    """Enforce INV-F6-METRIC-01: Reject any label key not in ALLOWED_METRIC_LABELS

    or present in FORBIDDEN_HIGH_CARDINALITY_LABELS.
    """
    keys = list(labels.keys()) if isinstance(labels, Mapping) else list(labels)
    for label in keys:
        l_lower = str(label).lower()
        if l_lower in FORBIDDEN_HIGH_CARDINALITY_LABELS or l_lower not in ALLOWED_METRIC_LABELS:
            raise ValueError(
                f"Forbidden metric label '{label}' rejected by INV-F6-METRIC-01: "
                f"High-cardinality label '{label}' rejected at metric registration time."
            )


class MetricsRegistry:
    """Facade for KarsaSec operational metrics (Sprint F6B).

    Provides structured counters, gauges, and histograms. Decouples core engine
    business logic from raw Prometheus metric mechanics.
    """

    def __init__(self, namespace: str = "karsasec") -> None:
        self._namespace = namespace
        self._lock = threading.Lock()
        # Storage for in-memory series snapshots
        # Series key format: (metric_name, frozen_tuple_of_sorted_labels)
        self._counters: dict[tuple[str, tuple[tuple[str, str], ...]], float] = collections.defaultdict(float)
        self._gauges: dict[tuple[str, tuple[tuple[str, str], ...]], float] = collections.defaultdict(float)
        self._histograms: dict[tuple[str, tuple[tuple[str, str], ...]], list[float]] = collections.defaultdict(list)

    def _canonicalize_labels(self, labels: Mapping[str, str] | None) -> tuple[tuple[str, str], ...]:
        if not labels:
            return ()
        validate_metric_labels(labels)
        return tuple(sorted((str(k), str(v)) for k, v in labels.items()))

    # ---------------------------------------------------------------------------
    # Counter Operations
    # ---------------------------------------------------------------------------

    def inc_counter(self, name: str, value: float = 1.0, labels: Mapping[str, str] | None = None) -> None:
        """Increment a counter metric safely."""
        try:
            canon = self._canonicalize_labels(labels)
            metric_key = (f"{self._namespace}_{name}", canon)
            with self._lock:
                self._counters[metric_key] += max(0.0, value)
        except ValueError:
            raise  # Re-raise explicit label validation errors for tests
        except Exception as err:
            default_logger.warning(
                "METRIC_INC_FAILED", f"Failed to increment counter '{name}': {err}", component="metrics"
            )

    # ---------------------------------------------------------------------------
    # Gauge Operations
    # ---------------------------------------------------------------------------

    def set_gauge(self, name: str, value: float, labels: Mapping[str, str] | None = None) -> None:
        """Set a gauge metric safely."""
        try:
            canon = self._canonicalize_labels(labels)
            metric_key = (f"{self._namespace}_{name}", canon)
            with self._lock:
                self._gauges[metric_key] = float(value)
        except ValueError:
            raise
        except Exception as err:
            default_logger.warning("METRIC_SET_FAILED", f"Failed to set gauge '{name}': {err}", component="metrics")

    # ---------------------------------------------------------------------------
    # Histogram Operations
    # ---------------------------------------------------------------------------

    def observe_histogram(self, name: str, amount: float, labels: Mapping[str, str] | None = None) -> None:
        """Observe a duration/value in a histogram metric safely."""
        try:
            canon = self._canonicalize_labels(labels)
            metric_key = (f"{self._namespace}_{name}", canon)
            with self._lock:
                self._histograms[metric_key].append(float(amount))
        except ValueError:
            raise
        except Exception as err:
            default_logger.warning(
                "METRIC_OBSERVE_FAILED", f"Failed to observe histogram '{name}': {err}", component="metrics"
            )

    @contextlib.contextmanager
    def timer(self, histogram_name: str, labels: Mapping[str, str] | None = None) -> Generator[None, None, None]:
        """Context manager to measure and observe execution time in seconds."""
        start = time.perf_counter()
        try:
            yield
        finally:
            duration = time.perf_counter() - start
            self.observe_histogram(histogram_name, duration, labels=labels)

    # ---------------------------------------------------------------------------
    # Business-Level Telemetry Methods (Domain Helpers)
    # ---------------------------------------------------------------------------

    def task_transition(
        self,
        state: str = "",
        result: str = "success",
        component: str = "task_repository",
        operation: str = "transition",
    ) -> None:
        labels = {"state": state, "result": result, "component": component, "operation": operation}
        self.inc_counter("task_transition_total", 1.0, labels=labels)

    def task_transition_failed(
        self,
        state: str = "",
        result: str = "failure",
        component: str = "task_repository",
        operation: str = "transition",
    ) -> None:
        labels = {"state": state, "result": result, "component": component, "operation": operation}
        self.inc_counter("task_transition_failed_total", 1.0, labels=labels)

    def observe_task_transition_duration(self, seconds: float, state: str = "", result: str = "success") -> None:
        labels = {"state": state, "result": result, "component": "task_repository", "operation": "transition"}
        self.observe_histogram("task_transition_duration_seconds", seconds, labels=labels)

    def worker_registered(self, result: str = "success") -> None:
        self.inc_counter(
            "worker_registration_total",
            1.0,
            labels={"result": result, "component": "worker_repository", "operation": "register"},
        )

    def worker_heartbeat(self, result: str = "success") -> None:
        self.inc_counter(
            "worker_heartbeat_total",
            1.0,
            labels={"result": result, "component": "worker_repository", "operation": "heartbeat"},
        )

    def worker_heartbeat_rejected(self, result: str = "rejected") -> None:
        self.inc_counter(
            "worker_heartbeat_rejected_total",
            1.0,
            labels={"result": result, "component": "worker_repository", "operation": "heartbeat"},
        )

    def set_active_workers(self, count: int) -> None:
        self.set_gauge("active_workers", count)

    def lease_acquired(self, result: str = "success") -> None:
        self.inc_counter(
            "lease_acquired_total", 1.0, labels={"result": result, "component": "recovery_lock", "operation": "acquire"}
        )

    def lease_renewed(self, result: str = "success") -> None:
        self.inc_counter(
            "lease_renewed_total", 1.0, labels={"result": result, "component": "recovery_lock", "operation": "renew"}
        )

    def lease_fenced(self, result: str = "fenced") -> None:
        self.inc_counter(
            "lease_fenced_total", 1.0, labels={"result": result, "component": "recovery_lock", "operation": "fence"}
        )

    def set_active_leases(self, count: int) -> None:
        self.set_gauge("active_leases", count)

    def observe_lease_acquisition_duration(self, seconds: float) -> None:
        self.observe_histogram(
            "lease_acquisition_duration_seconds",
            seconds,
            labels={"result": "success", "component": "recovery_lock", "operation": "acquire"},
        )

    def outbox_created(self, result: str = "created") -> None:
        self.inc_counter(
            "outbox_created_total", 1.0, labels={"result": result, "component": "outbox", "operation": "create"}
        )

    def outbox_published(self, result: str = "success") -> None:
        self.inc_counter(
            "outbox_published_total", 1.0, labels={"result": result, "component": "outbox", "operation": "publish"}
        )

    def outbox_retry(self, result: str = "retry") -> None:
        self.inc_counter(
            "outbox_retry_total", 1.0, labels={"result": result, "component": "outbox", "operation": "retry"}
        )

    def outbox_failed(self, result: str = "failure") -> None:
        self.inc_counter(
            "outbox_failed_total", 1.0, labels={"result": result, "component": "outbox", "operation": "publish"}
        )

    def set_pending_outbox_events(self, count: int) -> None:
        self.set_gauge("pending_outbox_events", count)

    def observe_outbox_publish_duration(self, seconds: float) -> None:
        self.observe_histogram(
            "outbox_publish_duration_seconds",
            seconds,
            labels={"result": "success", "component": "outbox", "operation": "publish"},
        )

    def set_running_tasks(self, count: int) -> None:
        self.set_gauge("running_tasks", count)

    def set_queued_tasks(self, count: int) -> None:
        self.set_gauge("queued_tasks", count)

    def observe_recovery_duration(self, seconds: float) -> None:
        self.observe_histogram(
            "recovery_duration_seconds",
            seconds,
            labels={"result": "success", "component": "recovery_engine", "operation": "recover"},
        )

    # ---------------------------------------------------------------------------
    # Snapshots & Inspection
    # ---------------------------------------------------------------------------

    def get_series_count(self) -> int:
        """Return total active metric series count across counters, gauges, and histograms."""
        with self._lock:
            return len(self._counters) + len(self._gauges) + len(self._histograms)

    def get_counter_value(self, name: str, labels: Mapping[str, str] | None = None) -> float:
        canon = self._canonicalize_labels(labels) if labels else ()
        metric_key = (f"{self._namespace}_{name}", canon)
        with self._lock:
            return self._counters.get(metric_key, 0.0)

    def get_gauge_value(self, name: str, labels: Mapping[str, str] | None = None) -> float:
        canon = self._canonicalize_labels(labels) if labels else ()
        metric_key = (f"{self._namespace}_{name}", canon)
        with self._lock:
            return self._gauges.get(metric_key, 0.0)

    def snapshot(self) -> dict[str, Any]:
        """Return thread-safe snapshot for exporter rendering."""
        with self._lock:
            return {
                "counters": dict(self._counters),
                "gauges": dict(self._gauges),
                "histograms": {k: list(v) for k, v in self._histograms.items()},
            }


# Backwards-compatible MetricsCollector bridge
class MetricsCollector(MetricsRegistry):
    """Backwards-compatible bridge for Sprint F4 MetricsCollector callers."""

    MAX_METRIC_VALUE = 10_000_000

    def __init__(self) -> None:
        super().__init__(namespace="karsasec")

    @classmethod
    def validate_labels(cls, label_names: list[str] | dict[str, Any] | Mapping[str, str]) -> None:
        validate_metric_labels(label_names)

    def set_queue_depth(self, value: int) -> None:
        clamped = min(self.MAX_METRIC_VALUE, max(0, value))
        self.set_queued_tasks(clamped)

    def set_active_workers(self, value: int) -> None:
        super().set_active_workers(value)

    def set_running_tasks(self, value: int) -> None:
        super().set_running_tasks(value)

    def inc_completed_tasks(self, count: int = 1) -> None:
        self.task_transition(state="COMPLETED", result="success")

    def inc_failed_tasks(self, count: int = 1) -> None:
        self.task_transition_failed(state="FAILED", result="failure")

    def inc_retry_count(self, count: int = 1) -> None:
        self.outbox_retry(result="retry")

    def inc_recovery_count(self, count: int = 1) -> None:
        self.inc_counter(
            "task_recovery_total",
            float(count),
            labels={"result": "success", "component": "recovery_engine", "operation": "recover"},
        )

    @property
    def queue_depth(self) -> int:
        return int(self.get_gauge_value("queued_tasks"))

    @property
    def active_workers(self) -> int:
        return int(self.get_gauge_value("active_workers"))

    @property
    def running_tasks(self) -> int:
        return int(self.get_gauge_value("running_tasks"))

    @property
    def completed_tasks(self) -> int:
        return int(
            self.get_counter_value(
                "task_transition_total",
                labels={
                    "state": "COMPLETED",
                    "result": "success",
                    "component": "task_repository",
                    "operation": "transition",
                },
            )
        )

    @property
    def failed_tasks(self) -> int:
        return int(
            self.get_counter_value(
                "task_transition_failed_total",
                labels={
                    "state": "FAILED",
                    "result": "failure",
                    "component": "task_repository",
                    "operation": "transition",
                },
            )
        )

    @property
    def retry_count(self) -> int:
        return int(
            self.get_counter_value(
                "outbox_retry_total", labels={"result": "retry", "component": "outbox", "operation": "retry"}
            )
        )

    @property
    def recovery_count(self) -> int:
        return int(
            self.get_counter_value(
                "task_recovery_total",
                labels={"result": "success", "component": "recovery_engine", "operation": "recover"},
            )
        )

    def snapshot_legacy(self) -> dict[str, int]:
        return {
            "queue_depth": self.queue_depth,
            "active_workers": self.active_workers,
            "running_tasks": self.running_tasks,
            "completed_tasks": self.completed_tasks,
            "failed_tasks": self.failed_tasks,
            "retry_count": self.retry_count,
            "recovery_count": self.recovery_count,
        }


# Singleton registry instance
_default_metrics_registry: MetricsRegistry | None = None


def get_metrics_registry() -> MetricsRegistry:
    global _default_metrics_registry
    if _default_metrics_registry is None:
        _default_metrics_registry = MetricsRegistry()
    return _default_metrics_registry
