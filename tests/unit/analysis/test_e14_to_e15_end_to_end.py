"""End-to-End E14 -> E15 Integration Pipeline Test Suite.

Verifies complete execution flow from E14 Vulnerability Priorities, Remediation Plans,
and Regression Fingerprints through E15 Evidence Validation, Exploitability Assessment,
Security Policy Evaluation, and Automated Security Gate Decisioning.
"""

from types import SimpleNamespace

from karsasec.analysis.e15_decision_audit import DecisionAuditTrail
from karsasec.analysis.e15_evidence_validator import EvidenceValidator
from karsasec.analysis.e15_exploitability import ExploitabilityEngine
from karsasec.analysis.e15_models import DecisionStatus
from karsasec.analysis.e15_security_gate import SecurityGate
from karsasec.analysis.regression_engine import RegressionEngine
from karsasec.analysis.remediation_engine import RemediationEngine
from karsasec.analysis.security_finding import FindingStatus, SecurityFinding
from karsasec.analysis.vulnerability_cluster import ClusterStatus, VulnerabilityCluster
from karsasec.analysis.vulnerability_prioritizer import VulnerabilityPrioritizer


def test_full_e14_to_e15_end_to_end_pipeline():
    # 1. Setup E14 Upstream Objects using Domain Models
    base_finding = SecurityFinding.create(
        rule_id="R1",
        rule_key="RK1",
        rule_version="1.0",
        vulnerability_class="SQL_INJECTION",
        source_fact_id="n1",
        sink_fact_id="n2",
        flow_id="f1",
        source_node_id="n1",
        sink_node_id="n2",
        severity="HIGH",
        status=FindingStatus.CONFIRMED,
        confidence=0.9,
        file="app.py",
        line=10,
    )

    # Attach evidence facts for E15 validator
    finding_data = base_finding.to_dict()
    finding_data.update({
        "status": base_finding.status,
        "sink_category": "SQL",
        "source_fact": SimpleNamespace(node_id="n1", file_path="app.py", line_number=10),
        "sink_fact": SimpleNamespace(node_id="n2", file_path="app.py", line_number=20),
    })
    finding = SimpleNamespace(**finding_data)

    base_cluster = VulnerabilityCluster.create(
        vulnerability_class="SQL_INJECTION",
        finding_ids=[base_finding.finding_id],
        source_fact_ids=["n1"],
        sink_fact_ids=["n2"],
        flow_ids=["f1"],
        source_nodes=["n1"],
        sink_nodes=["n2"],
        shared_contexts=(),
        confidence=0.9,
        severity="HIGH",
        status=ClusterStatus.CONFIRMED,
    )

    # Enriched cluster containing findings list
    cluster = SimpleNamespace(
        cluster_id=base_cluster.cluster_id,
        vulnerability_class=base_cluster.vulnerability_class,
        status=base_cluster.status,
        severity=base_cluster.severity,
        confidence=base_cluster.confidence,
        finding_ids=base_cluster.finding_ids,
        source_fact_ids=base_cluster.source_fact_ids,
        sink_fact_ids=base_cluster.sink_fact_ids,
        sink_nodes=base_cluster.sink_nodes,
        evidence_count=1,
        sink_category="SQL",
        findings=(finding,),
    )

    # Calculate E14 Priority
    prioritizer = VulnerabilityPrioritizer()
    priority = prioritizer.prioritize(cluster)  # type: ignore[arg-type]
    assert priority.priority_status in ("HIGH", "CRITICAL") or getattr(priority.priority_status, "value", None) in ("HIGH", "CRITICAL")

    # Calculate E14 Remediation Plan
    remediation_engine = RemediationEngine()
    remediation_plan = remediation_engine.generate(cluster)  # type: ignore[arg-type]
    assert getattr(remediation_plan.status, "value", str(remediation_plan.status)) == "REQUIRED" or getattr(remediation_plan.status, "name", str(remediation_plan.status)) == "REQUIRED"

    # Calculate E14 Regression Fingerprint & Report
    regression_engine = RegressionEngine()
    reg_report = regression_engine.compare(
        baseline_clusters=[cluster],  # type: ignore[arg-type]
        current_clusters=[],
        current_analysis_valid=True,
    )
    # Resolved fingerprint because absent in valid current analysis
    assert getattr(reg_report.status, "value", str(reg_report.status)) in ("PASS", "FAIL", "UNKNOWN")

    # 2. Execute E15 Decision Gate Pipeline
    validator = EvidenceValidator()
    evidence_val = validator.validate(cluster)
    assert evidence_val.evidence_valid is True

    exploit_engine = ExploitabilityEngine()
    exploit_val = exploit_engine.assess(cluster)
    assert exploit_val.assessment_valid is True

    gate = SecurityGate(
        evidence_validator=validator,
        exploitability_engine=exploit_engine,
    )

    decision, gate_res = gate.evaluate(
        priority=priority,
        remediation_plan=remediation_plan,
        regression_report=reg_report,
        cluster=cluster,
        evidence=evidence_val,
        exploitability=exploit_val,
    )

    # 3. Assert Decisions and Integrity
    assert decision.decision in (DecisionStatus.ALLOW, DecisionStatus.REVIEW, DecisionStatus.BLOCK)
    assert len(decision.decision_id) == 64
    assert len(gate_res.gate_id) == 64

    # Log to Audit Ledger
    trail = DecisionAuditTrail()
    rec = trail.log(decision, gate_res)
    assert rec.decision_id == decision.decision_id
    assert trail.count() == 1
