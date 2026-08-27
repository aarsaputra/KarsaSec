"""Unit tests for Sprint E15 Security Decision models and SHA-256 identities."""

import pytest

from karsasec.analysis.e15_models import (
    DecisionStatus,
    EvidenceValidation,
    ExploitabilityAssessment,
    SecurityDecision,
    SecurityGateResult,
    SecurityPolicy,
)


def test_decision_status_enum_values():
    assert DecisionStatus.ALLOW == "ALLOW"
    assert DecisionStatus.BLOCK == "BLOCK"
    assert DecisionStatus.REVIEW == "REVIEW"
    assert DecisionStatus.UNKNOWN == "UNKNOWN"


def test_security_decision_deterministic_id():
    id1 = SecurityDecision.compute_decision_id(
        priority_id="PRIO-01",
        remediation_plan_id="PLAN-01",
        fingerprint_id="FP-01",
        decision=DecisionStatus.ALLOW,
        evidence_valid=True,
        exploitability_valid=True,
        regression_status="RESOLVED",
        policy_version="1.0.0",
    )
    id2 = SecurityDecision.compute_decision_id(
        priority_id="PRIO-01",
        remediation_plan_id="PLAN-01",
        fingerprint_id="FP-01",
        decision=DecisionStatus.ALLOW,
        evidence_valid=True,
        exploitability_valid=True,
        regression_status="RESOLVED",
        policy_version="1.0.0",
    )
    assert id1 == id2
    assert len(id1) == 64


def test_security_gate_result_deterministic_id():
    id1 = SecurityGateResult.compute_gate_id(
        decision_id="DEC-01",
        policy_id="POL-01",
        evaluated_rules=("Rule_01", "Rule_02"),
        failed_rules=(),
    )
    id2 = SecurityGateResult.compute_gate_id(
        decision_id="DEC-01",
        policy_id="POL-01",
        evaluated_rules=("Rule_02", "Rule_01"),
        failed_rules=(),
    )
    assert id1 == id2
    assert len(id1) == 64


def test_evidence_validation_bounds_guard():
    ev = EvidenceValidation(
        evidence_valid=True,
        completeness=float("nan"),
        contradictions=0,
        missing_dimensions=(),
        validation_reason="OK",
    )
    assert ev.evidence_valid is False
