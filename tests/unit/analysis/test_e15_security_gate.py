"""Unit tests for Security Gate controller and decision rules."""

from types import SimpleNamespace
import pytest

from karsasec.analysis.e15_models import DecisionStatus, EvidenceValidation, ExploitabilityAssessment
from karsasec.analysis.e15_security_gate import SecurityGate


def test_security_gate_unknown_on_invalid_evidence():
    gate = SecurityGate()
    bad_evidence = EvidenceValidation(
        evidence_valid=False,
        completeness=0.0,
        contradictions=1,
        missing_dimensions=("source_fact",),
        validation_reason="Missing source",
    )
    decision, gate_res = gate.evaluate(evidence=bad_evidence)
    assert decision.decision == DecisionStatus.UNKNOWN
    assert gate_res.unknown is True


def test_security_gate_block_on_regression():
    gate = SecurityGate()
    good_evidence = EvidenceValidation(True, 1.0, 0, (), "OK")
    good_exploitability = ExploitabilityAssessment(1.0, 1.0, 1.0, 1.0, 0.0, True, True, "OK")
    priority = SimpleNamespace(status="MEDIUM", priority_id="P1", confidence=0.9)
    plan = SimpleNamespace(status="RECOMMENDED", plan_id="PL1")
    reg_report = SimpleNamespace(status="FAIL", change="FAIL", fingerprint_id="FP1")

    decision, gate_res = gate.evaluate(
        priority=priority,
        remediation_plan=plan,
        regression_report=reg_report,
        evidence=good_evidence,
        exploitability=good_exploitability,
    )
    assert decision.decision == DecisionStatus.BLOCK
    assert gate_res.blocked is True


def test_security_gate_critical_confirmed_guard():
    gate = SecurityGate()
    good_evidence = EvidenceValidation(True, 1.0, 0, (), "OK")
    good_exploitability = ExploitabilityAssessment(1.0, 1.0, 1.0, 1.0, 0.0, True, True, "OK")
    priority = SimpleNamespace(status="CRITICAL", priority_id="P1", confidence=0.95)
    plan = SimpleNamespace(status="REQUIRED", plan_id="PL1")
    reg_report = SimpleNamespace(status="NOT_TESTED", change="NOT_TESTED", fingerprint_id="FP1")

    decision, gate_res = gate.evaluate(
        priority=priority,
        remediation_plan=plan,
        regression_report=reg_report,
        evidence=good_evidence,
        exploitability=good_exploitability,
    )
    assert decision.decision in (DecisionStatus.BLOCK, DecisionStatus.REVIEW)
    assert decision.decision != DecisionStatus.ALLOW
