"""Unit tests for SecurityFindingStore deduplication and deterministic sorting (INV-E12-RULE-17,24)."""

from karsasec.analysis.security_finding import FindingStatus, SecurityFinding
from karsasec.analysis.security_finding_store import SecurityFindingStore


def test_security_finding_store_deduplication() -> None:
    """Verifies that adding identical findings deduplicates based on finding_id."""
    store = SecurityFindingStore()

    finding1 = SecurityFinding.create(
        rule_id="r1",
        rule_key="E12-SQL-001",
        rule_version="1.0",
        vulnerability_class="SQL Injection",
        source_fact_id="sf1",
        sink_fact_id="sk1",
        flow_id="fl1",
        source_node_id="n1",
        sink_node_id="n5",
        severity="HIGH",
        status=FindingStatus.CONFIRMED,
        confidence=0.90,
    )

    finding2 = SecurityFinding.create(
        rule_id="r1",
        rule_key="E12-SQL-001",
        rule_version="1.0",
        vulnerability_class="SQL Injection",
        source_fact_id="sf1",
        sink_fact_id="sk1",
        flow_id="fl1",
        source_node_id="n1",
        sink_node_id="n5",
        severity="HIGH",
        status=FindingStatus.CONFIRMED,
        confidence=0.90,
    )

    assert store.add(finding1) is True
    assert store.add(finding2) is False
    assert store.count() == 1


def test_security_finding_store_deterministic_sorting() -> None:
    """Verifies deterministic sorting by severity rank and rule_key."""
    store = SecurityFindingStore()

    f_high = SecurityFinding.create(
        rule_id="r1",
        rule_key="E12-SQL-001",
        rule_version="1.0",
        vulnerability_class="SQL Injection",
        source_fact_id="sf1",
        sink_fact_id="sk1",
        flow_id="fl1",
        source_node_id="n1",
        sink_node_id="n5",
        severity="HIGH",
        status=FindingStatus.CONFIRMED,
        confidence=0.90,
    )

    f_critical = SecurityFinding.create(
        rule_id="r2",
        rule_key="E12-CMD-001",
        rule_version="1.0",
        vulnerability_class="Command Injection",
        source_fact_id="sf2",
        sink_fact_id="sk2",
        flow_id="fl2",
        source_node_id="n1",
        sink_node_id="n5",
        severity="CRITICAL",
        status=FindingStatus.CONFIRMED,
        confidence=0.95,
    )

    store.add(f_high)
    store.add(f_critical)

    all_findings = store.all()
    assert len(all_findings) == 2
    assert all_findings[0].severity == "CRITICAL"
    assert all_findings[1].severity == "HIGH"
