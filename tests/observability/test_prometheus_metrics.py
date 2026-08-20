"""Unit, Cardinality, Exporter, and Resilience tests for Prometheus Telemetry Engine (Sprint F6B)."""

from __future__ import annotations

import pytest

from karsasec.observability.metrics import (
    MetricsRegistry,
    validate_metric_labels,
)
from karsasec.observability.prometheus_exporter import PrometheusExporter
from karsasec.persistence.db import DatabaseSessionFactory
from karsasec.persistence.models import Base
from karsasec.persistence.postgres_task_repository import PostgresTaskRepository
from karsasec.workers.task import RemediationTask, TaskState


class TestMetricsRegistryInit:
    def test_metrics_registry_initializes(self):
        registry = MetricsRegistry()
        assert registry.get_series_count() == 0

    def test_expected_counters_exist(self):
        registry = MetricsRegistry()
        registry.task_transition(state="RUNNING", result="success")
        registry.task_transition_failed(state="FAILED", result="failure")
        registry.worker_registered()
        registry.worker_heartbeat()
        registry.worker_heartbeat_rejected()
        registry.lease_acquired()
        registry.lease_renewed()
        registry.lease_fenced()
        registry.outbox_created()
        registry.outbox_published()
        registry.outbox_retry()
        registry.outbox_failed()

        assert (
            registry.get_counter_value(
                "task_transition_total",
                labels={
                    "state": "RUNNING",
                    "result": "success",
                    "component": "task_repository",
                    "operation": "transition",
                },
            )
            == 1.0
        )
        assert (
            registry.get_counter_value(
                "task_transition_failed_total",
                labels={
                    "state": "FAILED",
                    "result": "failure",
                    "component": "task_repository",
                    "operation": "transition",
                },
            )
            == 1.0
        )
        assert (
            registry.get_counter_value(
                "worker_registration_total",
                labels={"result": "success", "component": "worker_repository", "operation": "register"},
            )
            == 1.0
        )

    def test_expected_gauges_exist(self):
        registry = MetricsRegistry()
        registry.set_active_workers(5)
        registry.set_active_leases(2)
        registry.set_pending_outbox_events(10)
        registry.set_running_tasks(3)
        registry.set_queued_tasks(7)

        assert registry.get_gauge_value("active_workers") == 5.0
        assert registry.get_gauge_value("active_leases") == 2.0
        assert registry.get_gauge_value("pending_outbox_events") == 10.0
        assert registry.get_gauge_value("running_tasks") == 3.0
        assert registry.get_gauge_value("queued_tasks") == 7.0

    def test_expected_histograms_exist(self):
        registry = MetricsRegistry()
        registry.observe_task_transition_duration(0.045, state="RUNNING")
        registry.observe_lease_acquisition_duration(0.012)
        registry.observe_outbox_publish_duration(0.008)
        registry.observe_recovery_duration(0.120)

        snap = registry.snapshot()
        histograms = snap.get("histograms", {})
        assert len(histograms) == 4


class TestCardinalitySafetyINVF6METRIC01:
    @pytest.mark.parametrize(
        "forbidden_label",
        [
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
        ],
    )
    def test_dynamic_identifiers_rejected_as_metric_labels(self, forbidden_label: str):
        registry = MetricsRegistry()
        with pytest.raises(ValueError, match="Forbidden metric label"):
            validate_metric_labels({forbidden_label: "dynamic_val_123"})

        with pytest.raises(ValueError, match="Forbidden metric label"):
            registry.inc_counter("test_counter", 1.0, labels={forbidden_label: "val_123"})

    def test_allowed_labels_are_accepted(self):
        registry = MetricsRegistry()
        valid_labels = {
            "state": "RUNNING",
            "result": "success",
            "component": "task_repository",
            "operation": "transition",
        }
        validate_metric_labels(valid_labels)
        registry.inc_counter("allowed_metric", 1.0, labels=valid_labels)
        assert registry.get_counter_value("allowed_metric", labels=valid_labels) == 1.0

    def test_bounded_series_under_1000_dynamic_task_ids(self):
        """Adversarial Cardinality Test: Simulate 1,000 task transitions.

        Assert total metric series count remains strictly bounded (does NOT grow to 1,000 series).
        """
        registry = MetricsRegistry()

        for i in range(1, 1001):
            task_id = f"task-uuid-adversarial-{i:04d}"
            # Core domain operation: metric recording uses fixed static labels only
            registry.task_transition(state="RUNNING", result="success")

        # Total series count for task_transition_total MUST be exactly 1
        series_count = registry.get_series_count()
        assert series_count == 1, f"Cardinality Explosion! Expected 1 series, found {series_count}"


class TestPrometheusExporter:
    def test_metrics_endpoint_prometheus_format(self):
        registry = MetricsRegistry()
        registry.task_transition(state="QUEUED", result="success")
        registry.set_active_workers(4)

        exporter = PrometheusExporter(registry)
        output = exporter.generate_metrics_text()

        assert "# HELP karsasec_task_transition_total" in output
        assert "# TYPE karsasec_task_transition_total counter" in output
        assert (
            'karsasec_task_transition_total{component="task_repository",operation="transition",result="success",state="QUEUED"} 1.0'
            in output
        )
        assert "# HELP karsasec_active_workers" in output
        assert "# TYPE karsasec_active_workers gauge" in output
        assert "karsasec_active_workers 4.0" in output

    def test_metrics_endpoint_contains_no_secrets(self):
        registry = MetricsRegistry()
        registry.task_transition(state="COMPLETED", result="success")

        exporter = PrometheusExporter(registry)
        output = exporter.generate_metrics_text()

        for secret_term in ("password", "auth_token", "secret", "jwt", "api_key", "database_url"):
            assert secret_term not in output.lower(), (
                f"Privacy boundary violation: secret term '{secret_term}' leaked in /metrics"
            )

    def test_metrics_endpoint_contains_no_dynamic_identifiers(self):
        registry = MetricsRegistry()
        registry.task_transition(state="COMPLETED", result="success")

        exporter = PrometheusExporter(registry)
        output = exporter.generate_metrics_text()

        for forbidden_id in ("task_id=", "worker_id=", "lease_id=", "fencing_token=", "correlation_id="):
            assert forbidden_id not in output.lower(), (
                f"Cardinality explosion risk: dynamic id '{forbidden_id}' in /metrics output"
            )


class TestMetricFailureIsolation:
    def test_metric_failure_does_not_break_task_repository_transition(self, tmp_path):
        db_file = tmp_path / "test_f6b_metrics.db"
        factory = DatabaseSessionFactory(url=f"sqlite:///{db_file}")
        Base.metadata.create_all(bind=factory.engine)

        class FailingMetricsRegistry(MetricsRegistry):
            def task_transition(self, *args, **kwargs):
                raise RuntimeError("Prometheus collector backend deadlocked!")

        failing_metrics = FailingMetricsRegistry()
        task_repo = PostgresTaskRepository(session_factory=factory, metrics_registry=failing_metrics)

        task = RemediationTask(
            task_id="tsk-metric-fail-1",
            finding_id="f-1",
            approval_token_id="tok-1",
            token="secret",
            fingerprint="fp-metric-1",
            state=TaskState.PENDING,
        )
        task_repo.create_task(task)

        # Atomic transition MUST succeed cleanly despite FailingMetricsRegistry throwing RuntimeError
        result_task = task_repo.atomic_transition("tsk-metric-fail-1", 1, [TaskState.PENDING], TaskState.QUEUED)
        assert result_task.state == TaskState.QUEUED

        factory.close()
