"""TelemetryDashboard — Cluster Telemetry & Observability Formatter (Sprint F4).

Formats cluster telemetry snapshots for administrative monitoring and UI dashboards.

Invariants:
  - R7-R9: Privacy Boundary — no source code, diffs, credentials, or tokens included.
"""

from __future__ import annotations

from typing import Any
from karsasec.observability.metrics import MetricsCollector
from karsasec.observability.health import ClusterHealthMonitor


class TelemetryDashboard:
    """Formatter for aggregated cluster telemetry."""

    def __init__(
        self,
        metrics: MetricsCollector,
        health_monitor: ClusterHealthMonitor | None = None,
    ) -> None:
        self._metrics = metrics
        self._health = health_monitor

    def render_summary(self) -> dict[str, Any]:
        """Render aggregated telemetry summary dictionary."""
        snapshot = self._metrics.snapshot()
        health_report = self._health.get_health_report() if self._health else {"status": "UNKNOWN"}

        return {
            "cluster_health": health_report.get("status"),
            "metrics": snapshot,
            "components": health_report.get("components", {}),
        }
