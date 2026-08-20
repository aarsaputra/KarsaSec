"""PrometheusExporter — Standard Prometheus Exporter Engine (Sprint F4).

Formats cluster metrics into standard Prometheus Exposition Format for scraping (/metrics).

Exposed Metrics:
  - karsasec_queue_depth
  - karsasec_active_workers
  - karsasec_task_completed_total
  - karsasec_task_failed_total
  - karsasec_task_retry_total
  - karsasec_task_recovery_total

Invariants:
  - R7-R9: Privacy Boundary — strictly scalar metric values.
    Zero source code, diffs, patches, tokens, credentials, or API keys exposed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from karsasec.observability.metrics import MetricsCollector


class PrometheusExporter:
    """Generates Prometheus text exposition format metrics."""

    FORBIDDEN_TERMS = {
        "source_code", "unified_diff", "diff", "patch", "token", "credential", "api_key", "secret"
    }

    def __init__(self, metrics_collector: "MetricsCollector") -> None:
        self._collector = metrics_collector

    FORBIDDEN_HIGH_CARDINALITY_LABELS = {
        "task_id", "receipt_id", "finding_id", "trace_id", "span_id", "user_id", "tenant_id", "request_id", "session_id"
    }

    def register_metric(self, metric_name: str, label_names: list[str] | dict[str, str]) -> None:
        """Register metric with early label validation at registration API call."""
        from karsasec.observability.metrics import MetricsCollector
        MetricsCollector.validate_labels(label_names)
        self._collector.register_metric(metric_name, list(label_names) if isinstance(label_names, (list, set, tuple)) else list(label_names.keys()))

    def generate_metrics_text(self) -> str:
        """Render Prometheus exposition format string."""
        snapshot = self._collector.snapshot()

        lines = [
            "# HELP karsasec_queue_depth Current number of tasks waiting in queue.",
            "# TYPE karsasec_queue_depth gauge",
            f"karsasec_queue_depth {snapshot.get('queue_depth', 0)}",
            "",
            "# HELP karsasec_active_workers Number of registered online workers.",
            "# TYPE karsasec_active_workers gauge",
            f"karsasec_active_workers {snapshot.get('active_workers', 0)}",
            "",
            "# HELP karsasec_running_tasks Number of tasks currently executing.",
            "# TYPE karsasec_running_tasks gauge",
            f"karsasec_running_tasks {snapshot.get('running_tasks', 0)}",
            "",
            "# HELP karsasec_task_completed_total Total number of successfully completed tasks.",
            "# TYPE karsasec_task_completed_total counter",
            f"karsasec_task_completed_total {snapshot.get('completed_tasks', 0)}",
            "",
            "# HELP karsasec_task_failed_total Total number of permanently failed tasks.",
            "# TYPE karsasec_task_failed_total counter",
            f"karsasec_task_failed_total {snapshot.get('failed_tasks', 0)}",
            "",
            "# HELP karsasec_task_retry_total Total number of task retry attempts.",
            "# TYPE karsasec_task_retry_total counter",
            f"karsasec_task_retry_total {snapshot.get('retry_count', 0)}",
            "",
            "# HELP karsasec_task_recovery_total Total number of recovered stale tasks.",
            "# TYPE karsasec_task_recovery_total counter",
            f"karsasec_task_recovery_total {snapshot.get('recovery_count', 0)}",
            "",
        ]

        text_output = "\n".join(lines)

        # Point 6: Cardinality Protection Audit
        for label in self.FORBIDDEN_HIGH_CARDINALITY_LABELS:
            if f'{label}=' in text_output.lower():
                raise ValueError(
                    f"Cardinality Explosion Risk: High-cardinality label '{label}' detected in Prometheus metrics output."
                )

        # Audit sanity check: Privacy verification
        for forbidden in self.FORBIDDEN_TERMS:
            if forbidden in text_output.lower():
                raise ValueError(
                    f"Privacy Boundary Violation: Forbidden string '{forbidden}' in Prometheus output."
                )

        return text_output
