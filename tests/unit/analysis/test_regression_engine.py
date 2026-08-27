"""Unit tests for RegressionEngine and strict RESOLVED semantics."""

from __future__ import annotations

from karsasec.analysis.regression_engine import RegressionEngine
from karsasec.analysis.regression_report import RegressionStatus
from karsasec.analysis.vulnerability_cluster import ClusterStatus, VulnerabilityCluster


def test_regression_engine_strict_resolved() -> None:
    """Case AC, AD & INV-E14-PRIO-18,19: Missing current evidence or invalid analysis MUST emit UNKNOWN, never RESOLVED."""
    base_cluster = VulnerabilityCluster.create(
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

    engine = RegressionEngine()

    # Valid current run without baseline cluster -> RESOLVED
    report_valid = engine.compare([base_cluster], [], current_analysis_valid=True)
    assert len(report_valid.resolved_fingerprints) == 1
    assert report_valid.status == RegressionStatus.PASS

    # Invalid current run (analyzer crashed / evidence missing) -> UNKNOWN
    report_invalid = engine.compare([base_cluster], [], current_analysis_valid=False)
    assert len(report_invalid.resolved_fingerprints) == 0
    assert len(report_invalid.unknown_fingerprints) == 1
    assert report_invalid.status == RegressionStatus.UNKNOWN
