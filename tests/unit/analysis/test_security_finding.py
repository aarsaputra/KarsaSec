"""Unit tests for SecurityFinding model and deterministic finding_id generation (INV-E12-RULE-02,16)."""

from karsasec.analysis.security_finding import FindingStatus, SecurityFinding, compute_finding_id


def test_security_finding_deterministic_id() -> None:
    """Verifies that compute_finding_id produces identical SHA-256 identity."""
    fid1 = compute_finding_id(
        rule_id="rule_sql_id",
        rule_version="1.0",
        flow_id="flow_123_id",
        source_fact_id="fact_src",
        sink_fact_id="fact_snk",
    )
    fid2 = compute_finding_id(
        rule_id="rule_sql_id",
        rule_version="1.0",
        flow_id="flow_123_id",
        source_fact_id="fact_src",
        sink_fact_id="fact_snk",
    )
    assert fid1 == fid2
    assert len(fid1) == 64

    finding = SecurityFinding.create(
        rule_id="rule_sql_id",
        rule_key="E12-SQL-001",
        rule_version="1.0",
        vulnerability_class="SQL Injection",
        source_fact_id="fact_src",
        sink_fact_id="fact_snk",
        flow_id="flow_123_id",
        source_node_id="n1",
        sink_node_id="n5",
        severity="HIGH",
        status=FindingStatus.CONFIRMED,
        confidence=0.95,
    )

    assert finding.finding_id == fid1
    assert finding.status == FindingStatus.CONFIRMED


def test_security_finding_to_dict_explainable() -> None:
    """Verifies complete explainable evidence serialization in to_dict() (INV-E12-RULE-24,25)."""
    finding = SecurityFinding.create(
        rule_id="rule_cmd_id",
        rule_key="E12-CMD-001",
        rule_version="1.0",
        vulnerability_class="Command Injection",
        source_fact_id="f1",
        sink_fact_id="f2",
        flow_id="fl1",
        source_node_id="n1",
        sink_node_id="n3",
        severity="CRITICAL",
        status=FindingStatus.CONFIRMED,
        confidence=0.90,
        source_evidence={"kind": "http_user_input"},
        sink_evidence={"category": "command_execution"},
    )
    data = finding.to_dict()
    assert data["finding_id"] == finding.finding_id
    assert data["severity"] == "CRITICAL"
    assert data["evidence"]["source"]["kind"] == "http_user_input"
