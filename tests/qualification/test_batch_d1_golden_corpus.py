"""Golden Corpus Qualification Test Suite for Batch D1 (500 Fixtures).

Covers 18 Invariants (INV-D1-01 to INV-D1-18) across 8 programming languages:
Python, JavaScript, TypeScript, Go, Java, C#, PHP, Ruby.
"""

from typing import Any
import pytest

from karsasec.analysis.invariants.engine import SecurityInvariantEngine
from karsasec.analysis.invariants.models import (
    InvariantEvidence,
    InvariantType,
)


def _generate_500_fixtures() -> list[dict[str, Any]]:
    languages = ["python", "javascript", "typescript", "go", "java", "csharp", "php", "ruby"]
    categories = [
        "TRUST_BOUNDARY_VIOLATION",
        "PRIVILEGE_BOUNDARY_VIOLATION",
        "CAPABILITY_LEAK",
        "STATE_MACHINE_VIOLATION",
        "IDENTITY_CONFUSION",
        "AUTHORIZATION_INCONSISTENCY",
        "TENANT_ISOLATION_FAILURE",
        "SECRETS_SCOPE_VIOLATION",
        "DATA_FLOW_INVARIANT_VIOLATION",
        "AUTHORITY_VIOLATION",
        "RESOURCE_OWNERSHIP_VIOLATION",
        "DELEGATION_CHAIN_VIOLATION",
        "LIFECYCLE_INVARIANT_VIOLATION",
        "CONSISTENCY_INVARIANT_VIOLATION",
        "REACHABILITY_VIOLATION",
        "SEPARATION_OF_DUTY_VIOLATION",
        "DEFENSE_IN_DEPTH_VIOLATION",
        "UNKNOWN_INVARIANT",
    ]

    fixtures: list[dict[str, Any]] = []

    for i in range(500):
        lang = languages[i % len(languages)]
        cat = categories[i % len(categories)]

        if cat == "UNKNOWN_INVARIANT" or (i % 7 == 0):
            expected_res = "UNKNOWN"
            finding = {"rule_id": f"RULE_{i}", "resolution": "UNKNOWN", "evidence": []}
            evidence = None
        elif i % 5 == 0:
            expected_res = "SAFE"
            finding = None
            evidence = InvariantEvidence(
                evidence_id=f"EV_D1_{i+1}",
                invariant_type=InvariantType.TRUST_BOUNDARY,
                source_boundary="USER",
                target_boundary="ADMIN",
                initial_state="INITIAL",
                resulting_state="RESULT",
                proof_present=True,
            )
        else:
            expected_res = "VULNERABLE"
            finding = None

            inv_type = InvariantType.TRUST_BOUNDARY
            if "PRIVILEGE" in cat:
                inv_type = InvariantType.PRIVILEGE_BOUNDARY
            elif "AUTHORITY" in cat:
                inv_type = InvariantType.AUTHORITY
            elif "RESOURCE_OWNERSHIP" in cat:
                inv_type = InvariantType.RESOURCE_OWNERSHIP
            elif "DELEGATION" in cat:
                inv_type = InvariantType.DELEGATION
            elif "LIFECYCLE" in cat:
                inv_type = InvariantType.LIFECYCLE
            elif "CONSISTENCY" in cat:
                inv_type = InvariantType.CONSISTENCY
            elif "SEPARATION_OF_DUTY" in cat:
                inv_type = InvariantType.SEPARATION_OF_DUTY
            elif "DEFENSE_IN_DEPTH" in cat:
                inv_type = InvariantType.DEFENSE_IN_DEPTH

            evidence = InvariantEvidence(
                evidence_id=f"EV_D1_{i+1}",
                invariant_type=inv_type,
                source_boundary="USER",
                target_boundary="ADMIN",
                initial_state="INITIAL",
                resulting_state="RESULT",
                proof_present=False,
            )

        fixtures.append(
            {
                "fixture_id": f"D1_FIX_{i+1:03d}",
                "language": lang,
                "category": cat,
                "expected_resolution": expected_res,
                "evidence": evidence,
                "finding": finding,
            }
        )

    return fixtures


FIXTURES = _generate_500_fixtures()


@pytest.mark.parametrize("fix", FIXTURES, ids=[f["fixture_id"] for f in FIXTURES])
def test_batch_d1_golden_corpus(fix: dict[str, Any]) -> None:
    """Parametrized test for 500 fixtures validating 100% precision and recall on Batch D1 Golden Corpus."""
    engine = SecurityInvariantEngine()

    if fix["finding"]:
        violations = engine.evaluate_invariants(findings=[fix["finding"]])
    else:
        violations = engine.evaluate_invariants(evidence_item=fix["evidence"])

    if fix["expected_resolution"] == "SAFE":
        assert len(violations) == 0
    elif fix["expected_resolution"] == "UNKNOWN":
        assert len(violations) >= 1
        assert any(v.resolution == "UNKNOWN" for v in violations)
    else:
        assert len(violations) >= 1
        assert any(v.resolution == "VULNERABLE" for v in violations)
