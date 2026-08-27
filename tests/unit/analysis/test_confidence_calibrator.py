"""Unit tests for ConfidenceCalibrator, evidence diversity scoring, and duplicate finding isolation."""

from __future__ import annotations

from karsasec.analysis.confidence_calibrator import ConfidenceCalibrator
from karsasec.analysis.security_finding import FindingStatus, SecurityFinding
from karsasec.analysis.vulnerability_cluster import ClusterStatus


def test_confidence_calibrator_duplicate_isolation() -> None:
    """INV-E13-CORR-07: Duplicate findings MUST NOT inflate calibrated confidence."""
    f1 = SecurityFinding.create(
        rule_id="r1", rule_key="R1", rule_version="1.0", vulnerability_class="SQL_INJECTION",
        source_fact_id="sf1", sink_fact_id="kf1", flow_id="fl1", source_node_id="n1", sink_node_id="n2",
        severity="HIGH", status=FindingStatus.CONFIRMED, confidence=0.80,
    )
    f2 = SecurityFinding.create(
        rule_id="r1", rule_key="R1", rule_version="1.0", vulnerability_class="SQL_INJECTION",
        source_fact_id="sf1", sink_fact_id="kf1", flow_id="fl1", source_node_id="n1", sink_node_id="n2",
        severity="HIGH", status=FindingStatus.CONFIRMED, confidence=0.80,
    )

    calibrator = ConfidenceCalibrator()
    res1 = calibrator.calibrate([f1])
    res2 = calibrator.calibrate([f1, f2])

    assert res1.calibrated_confidence == res2.calibrated_confidence
    assert res1.calibrated_confidence == 0.80


def test_confidence_calibrator_severity_aggregation() -> None:
    """Verifies severity aggregation: max severity among non-blocked findings."""
    f1 = SecurityFinding.create(
        rule_id="r1", rule_key="R1", rule_version="1.0", vulnerability_class="SQL_INJECTION",
        source_fact_id="sf1", sink_fact_id="kf1", flow_id="fl1", source_node_id="n1", sink_node_id="n2",
        severity="HIGH", status=FindingStatus.CONFIRMED, confidence=0.90,
    )
    f2 = SecurityFinding.create(
        rule_id="r2", rule_key="R2", rule_version="1.0", vulnerability_class="SQL_INJECTION",
        source_fact_id="sf1", sink_fact_id="kf2", flow_id="fl2", source_node_id="n1", sink_node_id="n3",
        severity="CRITICAL", status=FindingStatus.CONFIRMED, confidence=0.90,
    )

    calibrator = ConfidenceCalibrator()
    res = calibrator.calibrate([f1, f2])

    assert res.severity == "CRITICAL"
    assert res.status == ClusterStatus.CONFIRMED
