"""Unit tests for RemediationEngine in tests/unit/analysis/test_remediation_engine.py."""

from __future__ import annotations

from karsasec.analysis.remediation_engine import RemediationEngine
from karsasec.analysis.remediation_pattern import RemediationStatus
from karsasec.analysis.vulnerability_cluster import ClusterStatus, VulnerabilityCluster


def test_remediation_engine_confirmed_vulnerability() -> None:
    """Verifies RemediationEngine generates REQUIRED status for CONFIRMED clusters."""
    cluster = VulnerabilityCluster.create(
        vulnerability_class="SQL_INJECTION",
        finding_ids=["f1"],
        source_fact_ids=["sf1"],
        sink_fact_ids=["kf1"],
        flow_ids=["fl1"],
        source_nodes=["n1"],
        sink_nodes=["n2"],
        shared_contexts=(),
        confidence=0.90,
        severity="HIGH",
        status=ClusterStatus.CONFIRMED,
    )

    engine = RemediationEngine()
    plan = engine.generate(cluster)

    assert plan.status == RemediationStatus.REQUIRED
    assert plan.primary_fix == "parameterized_query"
    assert plan.pattern_id == "REM-SQL-01"


def test_remediation_engine_blocked_vulnerability() -> None:
    """Verifies RemediationEngine generates BLOCKED status for BLOCKED clusters."""
    cluster = VulnerabilityCluster.create(
        vulnerability_class="SQL_INJECTION",
        finding_ids=["f1"],
        source_fact_ids=["sf1"],
        sink_fact_ids=["kf1"],
        flow_ids=["fl1"],
        source_nodes=["n1"],
        sink_nodes=["n2"],
        shared_contexts=(),
        confidence=0.90,
        severity="HIGH",
        status=ClusterStatus.BLOCKED,
    )

    engine = RemediationEngine()
    plan = engine.generate(cluster)

    assert plan.status == RemediationStatus.BLOCKED
