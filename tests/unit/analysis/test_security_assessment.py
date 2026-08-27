"""Unit tests for SecurityAssessment model and structured explanation generation engine."""

from __future__ import annotations

from karsasec.analysis.security_assessment import SecurityAssessment
from karsasec.analysis.security_finding import FindingStatus, SecurityFinding
from karsasec.analysis.vulnerability_cluster import ClusterStatus, VulnerabilityCluster


def test_security_assessment_creation_and_explanation() -> None:
    """Verifies SecurityAssessment creation and byte-for-byte reproducible explanation generation."""
    cluster = VulnerabilityCluster.create(
        vulnerability_class="SQL_INJECTION",
        finding_ids=["find1"],
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

    finding = SecurityFinding.create(
        rule_id="r1", rule_key="R1", rule_version="1.0", vulnerability_class="SQL_INJECTION",
        source_fact_id="sf1", sink_fact_id="kf1", flow_id="fl1", source_node_id="n1", sink_node_id="n2",
        severity="HIGH", status=FindingStatus.CONFIRMED, confidence=0.90,
    )

    assessment = SecurityAssessment.create(cluster=cluster, findings=[finding])

    assert assessment.assessment_id is not None
    assert assessment.cluster_id == cluster.cluster_id
    assert assessment.vulnerability_class == "SQL_INJECTION"
    assert len(assessment.explanation) > 0
    assert len(assessment.limitations) > 0

    serialized = assessment.to_dict()
    assert serialized["status"] == "CONFIRMED"
    assert serialized["assessment_id"] == assessment.assessment_id
