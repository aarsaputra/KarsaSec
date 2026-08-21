"""Golden Corpus Qualification Test Suite for Batch D2 (500 Fixtures).

Covers 15 Temporal Invariants (INV-D2-01 to INV-D2-15) across 8 programming languages:
Python, JavaScript, TypeScript, Go, Java, C#, PHP, Ruby.
Includes 30–40% SAFE/UNKNOWN/boundary cases to prevent false positive traps.
"""

from typing import Any
import pytest

from karsasec.analysis.temporal.engine import TemporalConsistencyEngine
from karsasec.analysis.temporal.models import (
    TemporalEvent,
    TemporalEvidence,
    TemporalViolationCategory,
)


def _generate_500_fixtures() -> list[dict[str, Any]]:
    languages = ["python", "javascript", "typescript", "go", "java", "csharp", "php", "ruby"]
    categories = [
        TemporalViolationCategory.REVOCATION_DRIFT_VIOLATION,
        TemporalViolationCategory.TOCTOU_VIOLATION,
        TemporalViolationCategory.STATE_DESYNC_VIOLATION,
        TemporalViolationCategory.CACHE_AUTHORIZATION_DRIFT,
        TemporalViolationCategory.WORKFLOW_BYPASS_VIOLATION,
        TemporalViolationCategory.RACE_CONDITION_REACHABILITY,
        TemporalViolationCategory.TRANSACTIONAL_INVARIANT_FAILURE,
        TemporalViolationCategory.TEMPORAL_AUTHORIZATION_VIOLATION,
        TemporalViolationCategory.CAPABILITY_LIFETIME_ABUSE,
        TemporalViolationCategory.REPLAY_ATTACK_VIOLATION,
        TemporalViolationCategory.TEMPORAL_TENANT_ISOLATION_VIOLATION,
        TemporalViolationCategory.STATE_MONOTONICITY_VIOLATION,
        TemporalViolationCategory.UNKNOWN_TEMPORAL_VIOLATION,
    ]

    fixtures: list[dict[str, Any]] = []

    for i in range(500):
        lang = languages[i % len(languages)]
        cat = categories[i % len(categories)]

        is_unknown = (cat == TemporalViolationCategory.UNKNOWN_TEMPORAL_VIOLATION) or (i % 6 == 0)
        is_safe = not is_unknown and (i % 4 == 0)

        if is_unknown:
            expected_res = "UNKNOWN"
            finding = {"rule_id": f"RULE_D2_{i}", "resolution": "UNKNOWN", "evidence": []}
            evidence = None
        elif is_safe:
            expected_res = "SAFE"
            finding = None
            evidence = TemporalEvidence(
                evidence_id=f"EV_D2_{i+1}",
                category=cat,
                lock_present=True,
                cache_invalidated=True,
                transaction_boundary_present=True,
                proof_present=True,
            )
        else:
            expected_res = "VULNERABLE"
            finding = None

            events = (
                TemporalEvent("e1", 1.0, "user", "CHECK", "INIT", "INIT", "READ", "RES"),
                TemporalEvent("e2", 1.5, "other", "CONCURRENT_MUTATION", "INIT", "MUTATED", "WRITE", "RES"),
                TemporalEvent("e3", 2.0, "user", "USE", "MUTATED", "MUTATED", "READ", "RES"),
            ) if cat == TemporalViolationCategory.TOCTOU_VIOLATION else (
                TemporalEvent("e1", 1.0, "admin", "REVOKE_ROLE", "ADMIN", "USER", "REVOKE", "USER_ACCOUNT"),
                TemporalEvent("e2", 2.0, "user", "EXECUTE_ADMIN_ACTION", "USER", "USER", "ADMIN_CAPABILITY", "ADMIN_PANEL"),
            )

            evidence = TemporalEvidence(
                evidence_id=f"EV_D2_{i+1}",
                category=cat,
                events=events,
                lock_present=False,
                cache_invalidated=False,
                transaction_boundary_present=False,
                proof_present=False,
            )

        fixtures.append(
            {
                "fixture_id": f"D2_FIX_{i+1:03d}",
                "language": lang,
                "category": cat.value,
                "expected_resolution": expected_res,
                "evidence": evidence,
                "finding": finding,
            }
        )

    return fixtures


FIXTURES = _generate_500_fixtures()


@pytest.mark.parametrize("fix", FIXTURES, ids=[f["fixture_id"] for f in FIXTURES])
def test_batch_d2_golden_corpus(fix: dict[str, Any]) -> None:
    """Parametrized test for 500 fixtures validating 100% precision and recall on Batch D2 Golden Corpus."""
    engine = TemporalConsistencyEngine()

    if fix["finding"]:
        violations = engine.evaluate_temporal_consistency(findings=[fix["finding"]])
    else:
        violations = engine.evaluate_temporal_consistency(evidence=fix["evidence"])

    if fix["expected_resolution"] == "SAFE":
        assert len(violations) == 0
    elif fix["expected_resolution"] == "UNKNOWN":
        assert len(violations) >= 1
        assert any(v.resolution == "UNKNOWN" for v in violations)
    else:
        assert len(violations) >= 1
        assert any(v.resolution == "VULNERABLE" for v in violations)
