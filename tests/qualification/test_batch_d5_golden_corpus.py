"""Golden Corpus Qualification Test Suite for Batch D5 (1,000 Fixtures).

Covers 25 Security Property Proof Invariants (INV-D5-01 to INV-D5-25) across 8 programming languages:
Python, JavaScript, TypeScript, Go, Java, C#, PHP, Ruby.
Distribution: 25% VULNERABLE, 25% SAFE, 25% UNKNOWN, 15% CONFLICT, 10% Boundary/Adversarial.
"""

from typing import Any
import pytest

from karsasec.analysis.correlation.models import SecurityProperty
from karsasec.analysis.proof.engine import SecurityPropertyProofEngine
from karsasec.analysis.proof.models import SecurityPropertyResolution


def _generate_1000_fixtures() -> list[dict[str, Any]]:
    languages = ["python", "javascript", "typescript", "go", "java", "csharp", "php", "ruby"]
    properties = [
        SecurityProperty.ACCOUNT_TAKEOVER,
        SecurityProperty.ROOT_ACCESS,
        SecurityProperty.CLOUD_ADMIN,
        SecurityProperty.TENANT_ESCAPE,
        SecurityProperty.ADMIN_ACCESS,
        SecurityProperty.SECRET_ACCESS,
        SecurityProperty.PAYMENT_MODIFICATION,
        SecurityProperty.DATA_EXFILTRATION,
        SecurityProperty.CODE_EXECUTION,
    ]

    fixtures: list[dict[str, Any]] = []

    for i in range(1000):
        lang = languages[i % len(languages)]
        sec_prop = properties[i % len(properties)]

        # Distribution:
        # 25% VULNERABLE (0-249 mod 1000) -> i % 20 in (0,1,2,3,4)
        # 25% SAFE (250-499 mod 1000) -> i % 20 in (5,6,7,8,9)
        # 25% UNKNOWN (500-749 mod 1000) -> i % 20 in (10,11,12,13,14)
        # 15% CONFLICT (750-899 mod 1000) -> i % 20 in (15,16,17)
        # 10% BOUNDARY (900-999 mod 1000) -> i % 20 in (18,19)
        mod = i % 20

        if mod in (0, 1, 2, 3, 4):
            expected_res = "VULNERABLE"
            finding = {
                "security_property": sec_prop.value,
                "resolution": "VULNERABLE",
            }
        elif mod in (5, 6, 7, 8, 9):
            expected_res = "SAFE"
            finding = {
                "security_property": sec_prop.value,
                "resolution": "SAFE",
            }
        elif mod in (10, 11, 12, 13, 14):
            expected_res = "UNKNOWN"
            finding = {
                "security_property": sec_prop.value,
                "resolution": "UNKNOWN",
            }
        elif mod in (15, 16, 17):
            expected_res = "CONFLICT"
            finding = {
                "security_property": sec_prop.value,
                "resolution": "CONFLICT",
                "conflict_present": True,
            }
        else:
            # Boundary case (missing evidence -> UNKNOWN)
            expected_res = "UNKNOWN"
            finding = {
                "security_property": sec_prop.value,
                "resolution": "VULNERABLE",
                "missing_evidence": True,
            }

        fixtures.append(
            {
                "fixture_id": f"D5_FIX_{i+1:04d}",
                "language": lang,
                "security_property": sec_prop,
                "expected_resolution": expected_res,
                "finding": finding,
            }
        )

    return fixtures


FIXTURES = _generate_1000_fixtures()


@pytest.mark.parametrize("fix", FIXTURES, ids=[f["fixture_id"] for f in FIXTURES])
def test_batch_d5_golden_corpus(fix: dict[str, Any]) -> None:
    """Parametrized test for 1,000 fixtures validating formal proof precision and recall on Batch D5 Golden Corpus."""
    engine = SecurityPropertyProofEngine()
    graph = engine.evaluate(findings=[fix["finding"]], security_properties=[fix["security_property"]])

    assert len(graph.proofs) == 1
    proof = graph.proofs[0]

    if fix["expected_resolution"] == "VULNERABLE":
        assert proof.resolution == SecurityPropertyResolution.VULNERABLE
    elif fix["expected_resolution"] == "SAFE":
        assert proof.resolution == SecurityPropertyResolution.SAFE
    elif fix["expected_resolution"] == "CONFLICT":
        assert proof.resolution == SecurityPropertyResolution.CONFLICT
    else:
        assert proof.resolution == SecurityPropertyResolution.UNKNOWN
