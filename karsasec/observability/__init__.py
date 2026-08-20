"""KarsaSec Observability, Telemetry & Metrics Module (Sprint F6).

Provides privacy-safe metrics collection, Prometheus exporting, cluster health monitoring,
structured JSON logging, and contextvars correlation management.
"""

from karsasec.observability.correlation import (
    correlation_id_var,
    correlation_scope,
    generate_correlation_id,
    get_correlation_id,
    get_operation_id,
    get_request_id,
    set_correlation_id,
    set_operation_id,
    set_request_id,
)
from karsasec.observability.health import ClusterHealthMonitor, HealthStatus
from karsasec.observability.logger import (
    JSONFormatter,
    StructuredLogger,
    default_logger,
    get_logger,
    redact_sensitive_data,
)
from karsasec.observability.metrics import (
    ALLOWED_METRIC_LABELS,
    FORBIDDEN_HIGH_CARDINALITY_LABELS,
    MetricsCollector,
    MetricsRegistry,
    get_metrics_registry,
    validate_metric_labels,
)
from karsasec.observability.prometheus_exporter import PrometheusExporter
from karsasec.observability.tracing import TraceContext, TraceManager

__all__ = [
    "MetricsCollector",
    "MetricsRegistry",
    "get_metrics_registry",
    "validate_metric_labels",
    "ALLOWED_METRIC_LABELS",
    "FORBIDDEN_HIGH_CARDINALITY_LABELS",
    "TraceContext",
    "TraceManager",
    "ClusterHealthMonitor",
    "HealthStatus",
    "PrometheusExporter",
    "StructuredLogger",
    "JSONFormatter",
    "default_logger",
    "get_logger",
    "redact_sensitive_data",
    "correlation_id_var",
    "get_correlation_id",
    "set_correlation_id",
    "get_request_id",
    "set_request_id",
    "get_operation_id",
    "set_operation_id",
    "correlation_scope",
    "generate_correlation_id",
]
