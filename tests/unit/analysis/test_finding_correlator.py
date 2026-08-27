"""Unit tests for FindingCorrelator, UnionFind algorithm, and evidence compatibility guards."""

from __future__ import annotations

from karsasec.analysis.finding_correlator import FindingCorrelator, UnionFind, evidence_compatible
from karsasec.analysis.security_finding import FindingStatus, SecurityFinding


def test_union_find_dsu_algorithm() -> None:
    """Verifies UnionFind component merging and path compression."""
    uf = UnionFind(["a", "b", "c", "d"])
    uf.union("a", "b")
    uf.union("c", "d")

    comps = uf.components()
    assert len(comps) == 2
    assert comps[0] == ["a", "b"]
    assert comps[1] == ["c", "d"]

    uf.union("b", "c")
    comps_merged = uf.components()
    assert len(comps_merged) == 1
    assert comps_merged[0] == ["a", "b", "c", "d"]


def test_evidence_compatible_guard() -> None:
    """Verifies evidence compatibility guard rules."""
    f1 = SecurityFinding.create(
        rule_id="r1", rule_key="R1", rule_version="1.0", vulnerability_class="SQL_INJECTION",
        source_fact_id="sf1", sink_fact_id="kf1", flow_id="fl1", source_node_id="n1", sink_node_id="n2",
        severity="HIGH", status=FindingStatus.CONFIRMED, confidence=0.90,
    )
    f2 = SecurityFinding.create(
        rule_id="r2", rule_key="R2", rule_version="1.0", vulnerability_class="SQL_INJECTION",
        source_fact_id="sf1", sink_fact_id="kf1", flow_id="fl1", source_node_id="n1", sink_node_id="n2",
        severity="HIGH", status=FindingStatus.CONFIRMED, confidence=0.90,
    )

    # Same flow & same vuln class -> compatible
    assert evidence_compatible(f1, f2) is True

    # Shared source but different sink & different vuln class -> incompatible
    f3 = SecurityFinding.create(
        rule_id="r3", rule_key="R3", rule_version="1.0", vulnerability_class="XSS",
        source_fact_id="sf1", sink_fact_id="kf99", flow_id="fl99", source_node_id="n1", sink_node_id="n99",
        severity="HIGH", status=FindingStatus.CONFIRMED, confidence=0.90,
    )
    assert evidence_compatible(f1, f3) is False


def test_finding_correlator_pipeline() -> None:
    """Verifies finding correlation pipeline into VulnerabilityClusters."""
    f1 = SecurityFinding.create(
        rule_id="r1", rule_key="R1", rule_version="1.0", vulnerability_class="SQL_INJECTION",
        source_fact_id="sf1", sink_fact_id="kf1", flow_id="fl1", source_node_id="n1", sink_node_id="n2",
        severity="HIGH", status=FindingStatus.CONFIRMED, confidence=0.90,
    )
    f2 = SecurityFinding.create(
        rule_id="r2", rule_key="R2", rule_version="1.0", vulnerability_class="SQL_INJECTION",
        source_fact_id="sf1", sink_fact_id="kf1", flow_id="fl1", source_node_id="n1", sink_node_id="n2",
        severity="HIGH", status=FindingStatus.CONFIRMED, confidence=0.90,
    )
    f3 = SecurityFinding.create(
        rule_id="r3", rule_key="R3", rule_version="1.0", vulnerability_class="XSS",
        source_fact_id="sf1", sink_fact_id="kf3", flow_id="fl3", source_node_id="n1", sink_node_id="n3",
        severity="HIGH", status=FindingStatus.CONFIRMED, confidence=0.90,
    )

    correlator = FindingCorrelator()
    clusters = correlator.correlate([f1, f2, f3])

    assert len(clusters) == 2
    classes = [c.vulnerability_class for c in clusters]
    assert "SQL_INJECTION" in classes
    assert "XSS" in classes
