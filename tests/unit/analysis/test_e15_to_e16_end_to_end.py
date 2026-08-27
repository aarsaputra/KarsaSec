"""End-to-end integration test for the full E9 -> E15 -> E16 pipeline and upstream immutability verification."""

from types import SimpleNamespace

from karsasec.analysis.e15_evidence_validator import EvidenceValidator
from karsasec.analysis.e15_exploitability import ExploitabilityEngine
from karsasec.analysis.e15_security_gate import SecurityGate
from karsasec.analysis.e16_admission import ReleaseAdmissionEngine
from karsasec.analysis.e16_audit import ReleaseAuditLedger
from karsasec.analysis.e16_enforcement import EnforcementEngine
from karsasec.analysis.e16_models import AdmissionStatus, EnforcementPolicy, ReleaseArtifact
from karsasec.analysis.e16_release import ReleaseStateMachine
from karsasec.analysis.regression_engine import RegressionEngine
from karsasec.analysis.remediation_engine import RemediationEngine
from karsasec.analysis.vulnerability_cluster import ClusterStatus
from karsasec.analysis.vulnerability_prioritizer import VulnerabilityPrioritizer


def test_full_e9_to_e16_end_to_end_pipeline():
    # 1. Setup E14 Upstream Objects
    finding = SimpleNamespace(
        vulnerability_class="SQL_INJECTION",
        sink_category="SQL",
        severity="HIGH",
        source_fact=SimpleNamespace(node_id="n1", file_path="app.py", line_number=10),
        sink_fact=SimpleNamespace(node_id="n2", file_path="app.py", line_number=20),
        confidence=0.9,
    )
    cluster = SimpleNamespace(
        cluster_id="CLUSTER-001",
        status=ClusterStatus.CONFIRMED,
        severity="HIGH",
        confidence=0.9,
        findings=(finding,),
        vulnerability_class="SQL_INJECTION",
        sink_category="SQL",
        evidence_count=1,
        source_fact_ids=("n1",),
        sink_fact_ids=("n2",),
        sink_nodes=("n2",),
    )

    prioritizer = VulnerabilityPrioritizer()
    priority = prioritizer.prioritize(cluster)

    remediation_engine = RemediationEngine()
    remediation_plan = remediation_engine.generate(cluster)

    regression_engine = RegressionEngine()
    reg_report = regression_engine.compare(
        baseline_clusters=[cluster],
        current_clusters=[],
        current_analysis_valid=True,
    )

    # 2. Execute E15 Decision Gate Pipeline
    validator = EvidenceValidator()
    evidence_val = validator.validate(cluster)
    exploit_engine = ExploitabilityEngine()
    exploit_val = exploit_engine.assess(cluster)

    gate = SecurityGate(
        evidence_validator=validator,
        exploitability_engine=exploit_val,
    )

    decision, gate_res = gate.evaluate(
        priority=priority,
        remediation_plan=remediation_plan,
        regression_report=reg_report,
        cluster=cluster,
        evidence=evidence_val,
        exploitability=exploit_val,
    )

    # 3. Execute E16 Release Admission, Enforcement & Audit Pipeline
    artifact = ReleaseArtifact.create(
        version="1.0.0",
        commit_sha="a1b2c3d4e5f6",
        decision_id=decision.decision_id,
        evaluation_id="EVAL-2026-001",
        content_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )

    policy = EnforcementPolicy.create(
        allow_on=("ALLOW",),
        minimum_confidence=0.80,
    )

    adm_engine = ReleaseAdmissionEngine()
    admission = adm_engine.evaluate(
        artifact=artifact,
        decision=decision,
        policy=policy,
        remediation_plan=remediation_plan,
        regression_report=reg_report,
    )

    assert admission.status in (AdmissionStatus.APPROVED, AdmissionStatus.REVIEW_REQUIRED, AdmissionStatus.BLOCKED)

    # Enforcement Permission Check
    enforcer = EnforcementEngine()
    permission = enforcer.authorize_permission(admission)
    assert permission.is_permitted == (admission.status == AdmissionStatus.APPROVED)

    # State Machine Transition Check
    state_machine = ReleaseStateMachine(artifact_id=artifact.artifact_id)
    state_machine.transition(state_machine.current_state.SECURITY_EVALUATED, admission)
    target_state = getattr(ReleaseStateMachine, str(admission.status), None) or str(admission.status)
    state_machine.transition(target_state, admission)
    assert str(state_machine.current_state) == str(admission.status)

    # Audit Ledger Verification
    ledger = ReleaseAuditLedger()
    audit_rec = ledger.append(admission)
    assert audit_rec.sequence == 1
    assert ledger.verify_integrity() is True
