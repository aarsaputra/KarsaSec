"""Unit tests for Decision Audit Trail."""

import pytest

from karsasec.analysis.e15_decision_audit import DecisionAuditTrail
from karsasec.analysis.e15_models import DecisionStatus, SecurityDecision, SecurityGateResult


def test_audit_trail_logging_and_retrieval():
    trail = DecisionAuditTrail()

    decision = SecurityDecision(
        decision_id="DEC-1234567890ABCDEF",
        priority_id="P1",
        remediation_plan_id="PL1",
        fingerprint_id="FP1",
        decision=DecisionStatus.ALLOW,
        confidence=0.95,
        rationale="Passed all tests",
        policy_version="1.0.0",
        evidence_valid=True,
        exploitability_valid=True,
        regression_status="RESOLVED",
    )

    gate_result = SecurityGateResult(
        gate_id="GATE-01",
        decision_id=decision.decision_id,
        passed=True,
        blocked=False,
        requires_review=False,
        unknown=False,
        failed_rules=(),
        evaluated_rules=("Rule_01", "Rule_10"),
        policy_version="1.0.0",
    )

    rec = trail.log(decision, gate_result)
    assert rec.decision_id == decision.decision_id
    assert trail.count() == 1

    fetched = trail.get(decision.decision_id)
    assert fetched == rec
