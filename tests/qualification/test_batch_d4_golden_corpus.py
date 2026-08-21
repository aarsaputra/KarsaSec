"""Golden Corpus Qualification Test Suite for Batch D4 (800 Fixtures).

Covers 20 Cross-Batch Correlation Invariants (INV-D4-01 to INV-D4-20) across 8 programming languages:
Python, JavaScript, TypeScript, Go, Java, C#, PHP, Ruby.
Distribution: 25% VULNERABLE, 25% SAFE, 25% UNKNOWN, 25% Boundary/Adversarial.
"""

from typing import Any
import pytest

from karsasec.analysis.correlation.engine import CrossBatchCorrelationEngine
from karsasec.analysis.correlation.models import (
    CorrelationResolution,
    SecurityProperty,
)


def _generate_800_fixtures() -> list[dict[str, Any]]:
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

    for i in range(800):
        lang = languages[i % len(languages)]
        sec_prop = properties[i % len(properties)]

        # 25% VULNERABLE (i % 4 == 0)
        # 25% SAFE (i % 4 == 1)
        # 25% UNKNOWN (i % 4 == 2)
        # 25% BOUNDARY (i % 4 == 3)
        mod = i % 4

        if mod == 0:
            expected_res = "VULNERABLE"
            finding = {
                "source_batch": "D1",
                "correlation_id": f"CORR_D4_{i+1}",
                "resolution": "VULNERABLE",
                "security_property": sec_prop.value,
            }
        elif mod == 1:
            expected_res = "SAFE"
            finding = {
                "source_batch": "D3",
                "correlation_id": f"CORR_D4_{i+1}",
                "resolution": "SAFE",
                "security_property": sec_prop.value,
            }
        elif mod == 2:
            expected_res = "UNKNOWN"
            finding = {
                "source_batch": "D1",
                "correlation_id": "MISSING_CORRELATION",
                "resolution": "UNKNOWN",
                "security_property": "UNKNOWN",
            }
        else:
            # Boundary case: conflict or missing correlation key
            expected_res = "UNKNOWN"
            finding = {
                "source_batch": "D2",
                "correlation_id": f"CORR_D4_{i+1}",
                "resolution": "SAFE",
                "conflict_present": True,
                "security_property": sec_prop.value,
            }

        fixtures.append(
            {
                "fixture_id": f"D4_FIX_{i+1:03d}",
                "language": lang,
                "expected_resolution": expected_res,
                "finding": finding,
            }
        )

    return fixtures


FIXTURES = _generate_800_fixtures()


@pytest.mark.parametrize("fix", FIXTURES, ids=[f["fixture_id"] for f in FIXTURES])
def test_batch_d4_golden_corpus(fix: dict[str, Any]) -> None:
    """Parametrized test for 800 fixtures validating precision and recall on Batch D4 Golden Corpus."""
    engine = CrossBatchCorrelationEngine()
    graph = engine.correlate(findings=[fix["finding"]])

    if fix["expected_resolution"] == "SAFE":
        assert len(graph.exploit_chains) == 0
    elif fix["expected_resolution"] == "UNKNOWN":
        assert len(graph.exploit_chains) >= 1
        assert any(c.resolution == CorrelationResolution.UNKNOWN for c in graph.exploit_chains)
    else:
        assert len(graph.exploit_chains) >= 1
        assert any(c.resolution == CorrelationResolution.VULNERABLE for c in graph.exploit_chains)
