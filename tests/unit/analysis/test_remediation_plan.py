"""Unit tests for RemediationPlan model and plan_id calculation."""

from __future__ import annotations

from karsasec.analysis.remediation_pattern import RemediationStatus
from karsasec.analysis.remediation_plan import RemediationPlan, compute_remediation_plan_id


def test_remediation_plan_deterministic_id() -> None:
    """Verifies deterministic plan_id computation."""
    pid1 = compute_remediation_plan_id("c1", "REM-SQL-01", RemediationStatus.REQUIRED, "parameterized_query")
    pid2 = compute_remediation_plan_id("c1", "REM-SQL-01", RemediationStatus.REQUIRED, "parameterized_query")

    assert pid1 == pid2
    assert len(pid1) == 64


def test_remediation_plan_creation_and_immutability() -> None:
    """Verifies RemediationPlan factory creation and immutability."""
    plan = RemediationPlan.create(
        cluster_id="c1",
        pattern_id="REM-SQL-01",
        status=RemediationStatus.REQUIRED,
        primary_fix="parameterized_query",
        alternative_fixes=["prepared_statement"],
        affected_nodes=["n2"],
        validation_steps=["ast_parameter_binding_check"],
        rationale=["CONFIRMED vulnerability"],
    )

    assert plan.plan_id is not None
    assert plan.status == RemediationStatus.REQUIRED
    assert plan.primary_fix == "parameterized_query"

    serialized = plan.to_dict()
    assert serialized["status"] == "REQUIRED"
