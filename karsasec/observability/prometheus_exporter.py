"""PrometheusExporter — Standard Prometheus Exposition Engine (Sprint F6B).

Formats registered metrics into standard Prometheus Exposition Format for scraping (/metrics).

Invariants:
  - INV-F6-METRIC-01: No high-cardinality or dynamic identifiers in labels.
  - Privacy Boundary: Zero source code, diffs, patches, tokens, credentials, or secrets.
"""

from __future__ import annotations


from karsasec.observability.metrics import (
    FORBIDDEN_HIGH_CARDINALITY_LABELS,
    FORBIDDEN_METRIC_KEYS,
    MetricsCollector,
    MetricsRegistry,
    get_metrics_registry,
)


class PrometheusExporter:
    """Generates Prometheus text exposition format metrics."""

    def __init__(self, metrics_registry: MetricsRegistry | MetricsCollector | None = None) -> None:
        self._registry = metrics_registry or get_metrics_registry()

    def register_metric(self, metric_name: str, label_names: list[str] | dict[str, str]) -> None:
        """Validate labels early at registration API call."""
        MetricsCollector.validate_labels(label_names)

    def _format_labels(self, labels_tuple: tuple[tuple[str, str], ...]) -> str:
        if not labels_tuple:
            return ""
        items = [f'{k}="{v}"' for k, v in labels_tuple]
        return "{" + ",".join(items) + "}"

    def generate_metrics_text(self) -> str:
        """Render Prometheus exposition format string."""
        if hasattr(self._registry, "snapshot") and callable(self._registry.snapshot):
            snap = self._registry.snapshot()
        else:
            snap = {}

        lines: list[str] = []

        # Render Counters
        counters: dict[tuple[str, tuple[tuple[str, str], ...]], float] = snap.get("counters", {})
        processed_counters: dict[str, list[tuple[tuple[tuple[str, str], ...], float]]] = {}
        for (name, labels_tuple), val in counters.items():
            processed_counters.setdefault(name, []).append((labels_tuple, val))

        for name, series_list in processed_counters.items():
            lines.append(f"# HELP {name} Counter metric for {name}.")
            lines.append(f"# TYPE {name} counter")
            for labels_tuple, val in series_list:
                label_str = self._format_labels(labels_tuple)
                lines.append(f"{name}{label_str} {val}")
            lines.append("")

        # Render Gauges
        gauges: dict[tuple[str, tuple[tuple[str, str], ...]], float] = snap.get("gauges", {})
        processed_gauges: dict[str, list[tuple[tuple[tuple[str, str], ...], float]]] = {}
        for (name, labels_tuple), val in gauges.items():
            processed_gauges.setdefault(name, []).append((labels_tuple, val))

        for name, series_list in processed_gauges.items():
            lines.append(f"# HELP {name} Gauge metric for {name}.")
            lines.append(f"# TYPE {name} gauge")
            for labels_tuple, val in series_list:
                label_str = self._format_labels(labels_tuple)
                lines.append(f"{name}{label_str} {val}")
            lines.append("")

        # Render Histograms
        histograms: dict[tuple[str, tuple[tuple[str, str], ...]], list[float]] = snap.get("histograms", {})
        processed_histograms: dict[str, list[tuple[tuple[tuple[str, str], ...], list[float]]]] = {}
        for (name, labels_tuple), values in histograms.items():
            processed_histograms.setdefault(name, []).append((labels_tuple, values))

        for name, series_list in processed_histograms.items():
            lines.append(f"# HELP {name} Histogram metric for {name}.")
            lines.append(f"# TYPE {name} histogram")
            for labels_tuple, values in series_list:
                label_str = self._format_labels(labels_tuple)
                count = len(values)
                total_sum = sum(values)
                lines.append(f"{name}_count{label_str} {count}")
                lines.append(f"{name}_sum{label_str} {total_sum}")
            lines.append("")

        # Legacy fallback if no counters/gauges/histograms present
        if isinstance(self._registry, MetricsCollector) and not lines:
            legacy_snap = self._registry.snapshot_legacy()
            lines.extend(
                [
                    "# HELP karsasec_queue_depth Current number of tasks waiting in queue.",
                    "# TYPE karsasec_queue_depth gauge",
                    f"karsasec_queue_depth {legacy_snap.get('queue_depth', 0)}",
                    "",
                    "# HELP karsasec_active_workers Number of registered online workers.",
                    "# TYPE karsasec_active_workers gauge",
                    f"karsasec_active_workers {legacy_snap.get('active_workers', 0)}",
                    "",
                    "# HELP karsasec_running_tasks Number of tasks currently executing.",
                    "# TYPE karsasec_running_tasks gauge",
                    f"karsasec_running_tasks {legacy_snap.get('running_tasks', 0)}",
                    "",
                    "# HELP karsasec_task_completed_total Total number of successfully completed tasks.",
                    "# TYPE karsasec_task_completed_total counter",
                    f"karsasec_task_completed_total {legacy_snap.get('completed_tasks', 0)}",
                    "",
                    "# HELP karsasec_task_failed_total Total number of permanently failed tasks.",
                    "# TYPE karsasec_task_failed_total counter",
                    f"karsasec_task_failed_total {legacy_snap.get('failed_tasks', 0)}",
                    "",
                    "# HELP karsasec_task_retry_total Total number of task retry attempts.",
                    "# TYPE karsasec_task_retry_total counter",
                    f"karsasec_task_retry_total {legacy_snap.get('retry_count', 0)}",
                    "",
                    "# HELP karsasec_task_recovery_total Total number of recovered stale tasks.",
                    "# TYPE karsasec_task_recovery_total counter",
                    f"karsasec_task_recovery_total {legacy_snap.get('recovery_count', 0)}",
                    "",
                ]
            )

        text_output = "\n".join(lines)

        # Cardinality Protection Audit: Ensure no forbidden high-cardinality labels appear in output
        for label in FORBIDDEN_HIGH_CARDINALITY_LABELS:
            if f"{label}=" in text_output.lower():
                raise ValueError(
                    f"Cardinality Explosion Risk: High-cardinality label '{label}' detected in Prometheus metrics output."
                )

        # Privacy Audit: Ensure no forbidden sensitive terms leak into output
        for forbidden in FORBIDDEN_METRIC_KEYS:
            if forbidden in text_output.lower():
                raise ValueError(f"Privacy Boundary Violation: Forbidden string '{forbidden}' in Prometheus output.")

        return text_output
