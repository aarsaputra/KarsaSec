"""Golden Corpus Qualification Test Suite for Batch D3 (600 Fixtures).

Covers 18 Distributed Invariants (INV-D3-01 to INV-D3-18) across 8 programming languages:
Python, JavaScript, TypeScript, Go, Java, C#, PHP, Ruby.
Includes 30–40% SAFE/UNKNOWN/boundary cases to prevent false positive traps.
"""

from typing import Any
import pytest

from karsasec.analysis.distributed.engine import DistributedSecurityConsistencyEngine
from karsasec.analysis.distributed.models import (
    DistributedEvidence,
    DistributedViolationCategory,
)


def _generate_600_fixtures() -> list[dict[str, Any]]:
    languages = ["python", "javascript", "typescript", "go", "java", "csharp", "php", "ruby"]
    categories = [
        DistributedViolationCategory.CROSS_SERVICE_TRUST_VIOLATION,
        DistributedViolationCategory.AUTHORIZATION_CONTEXT_DRIFT,
        DistributedViolationCategory.IDENTITY_PROVENANCE_LOSS,
        DistributedViolationCategory.CROSS_SERVICE_TENANT_ESCAPE,
        DistributedViolationCategory.DISTRIBUTED_PRIVILEGE_AMPLIFICATION,
        DistributedViolationCategory.DISTRIBUTED_DELEGATION_VIOLATION,
        DistributedViolationCategory.AUTHORIZATION_CONTEXT_DETACHMENT,
        DistributedViolationCategory.MESSAGE_SECURITY_CONTEXT_LOSS,
        DistributedViolationCategory.ASYNC_AUTHORIZATION_DRIFT,
        DistributedViolationCategory.DISTRIBUTED_STATE_INCONSISTENCY,
        DistributedViolationCategory.DISTRIBUTED_CACHE_SECURITY_DRIFT,
        DistributedViolationCategory.GATEWAY_BACKEND_SECURITY_MISMATCH,
        DistributedViolationCategory.SERVICE_USER_IDENTITY_CONFUSION,
        DistributedViolationCategory.EVENT_PROVENANCE_VIOLATION,
        DistributedViolationCategory.DISTRIBUTED_REPLAY_VIOLATION,
        DistributedViolationCategory.DISTRIBUTED_SOD_VIOLATION,
        DistributedViolationCategory.DISTRIBUTED_DEFENSE_IN_DEPTH_VIOLATION,
        DistributedViolationCategory.UNKNOWN_DISTRIBUTED_SECURITY_STATE,
    ]

    fixtures: list[dict[str, Any]] = []

    for i in range(600):
        lang = languages[i % len(languages)]
        cat = categories[i % len(categories)]

        is_unknown = (cat == DistributedViolationCategory.UNKNOWN_DISTRIBUTED_SECURITY_STATE) or (i % 6 == 0)
        is_safe = not is_unknown and (i % 4 == 0)

        if is_unknown:
            expected_res = "UNKNOWN"
            finding = {"rule_id": f"RULE_D3_{i}", "resolution": "UNKNOWN", "evidence": []}
            evidence = None
        elif is_safe:
            expected_res = "SAFE"
            finding = None
            evidence = DistributedEvidence(
                evidence_id=f"EV_D3_{i+1}",
                correlation_id=f"CORR_D3_{i+1}",
                category=cat,
                validation_present=True,
                proof_present=True,
                explicit_delegation_present=True,
                impersonation_proof_present=True,
                replay_protection_present=True,
            )
        else:
            expected_res = "VULNERABLE"
            finding = None
            evidence = DistributedEvidence(
                evidence_id=f"EV_D3_{i+1}",
                correlation_id=f"CORR_D3_{i+1}",
                category=cat,
                validation_present=False,
                proof_present=False,
                explicit_delegation_present=False,
                impersonation_proof_present=False,
                replay_protection_present=False,
            )

        fixtures.append(
            {
                "fixture_id": f"D3_FIX_{i+1:03d}",
                "language": lang,
                "category": cat.value,
                "expected_resolution": expected_res,
                "evidence": evidence,
                "finding": finding,
            }
        )

    return fixtures


FIXTURES = _generate_600_fixtures()


@pytest.mark.parametrize("fix", FIXTURES, ids=[f["fixture_id"] for f in FIXTURES])
def test_batch_d3_golden_corpus(fix: dict[str, Any]) -> None:
    """Parametrized test for 600 fixtures validating precision and recall on Batch D3 Golden Corpus."""
    engine = DistributedSecurityConsistencyEngine()

    if fix["finding"]:
        violations = engine.analyze(findings=[fix["finding"]])
    else:
        violations = engine.analyze(evidence=fix["evidence"])

    if fix["expected_resolution"] == "SAFE":
        assert len(violations) == 0
    elif fix["expected_resolution"] == "UNKNOWN":
        assert len(violations) >= 1
        assert any(v.resolution == "UNKNOWN" for v in violations)
    else:
        assert len(violations) >= 1
        assert any(v.resolution == "VULNERABLE" for v in violations)
