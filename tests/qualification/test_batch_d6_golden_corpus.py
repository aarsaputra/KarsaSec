"""Batch D6 Qualification Golden Corpus Test Suite.

Validates 1,200 fixtures across 8 programming languages:
- Python, JavaScript, TypeScript, Go, Java, PHP, C, Rust
Distribution:
- 20% VULNERABLE (240)
- 20% SAFE (240)
- 20% UNKNOWN (240)
- 15% CONFLICT (180)
- 15% duplicate/consolidation (180)
- 10% boundary/adversarial (120)
"""

from typing import Any
import pytest

from karsasec.analysis.decision.engine import SecurityDecisionEngine
from karsasec.analysis.decision.models import DecisionResolution

LANGUAGES = ["python", "javascript", "typescript", "go", "java", "php", "c", "rust"]


def _generate_d6_fixtures() -> list[dict[str, Any]]:
    fixtures: list[dict[str, Any]] = []

    # 1. 240 VULNERABLE fixtures
    for i in range(240):
        lang = LANGUAGES[i % len(LANGUAGES)]
        fixtures.append({
            "id": f"D6_FIX_VULN_{i:04d}",
            "language": lang,
            "expected_resolution": DecisionResolution.VULNERABLE,
            "raw_findings": [
                {
                    "security_property": "ACCOUNT_TAKEOVER",
                    "resolution": "VULNERABLE",
                    "root_cause_id": f"RC_VULN_{i}",
                    "language": lang,
                }
            ],
        })

    # 2. 240 SAFE fixtures
    for i in range(240):
        lang = LANGUAGES[i % len(LANGUAGES)]
        fixtures.append({
            "id": f"D6_FIX_SAFE_{i:04d}",
            "language": lang,
            "expected_resolution": DecisionResolution.SAFE,
            "raw_findings": [
                {
                    "security_property": "SECRET_ACCESS",
                    "resolution": "SAFE",
                    "root_cause_id": f"RC_SAFE_{i}",
                    "language": lang,
                }
            ],
        })

    # 3. 240 UNKNOWN fixtures
    for i in range(240):
        lang = LANGUAGES[i % len(LANGUAGES)]
        fixtures.append({
            "id": f"D6_FIX_UNK_{i:04d}",
            "language": lang,
            "expected_resolution": DecisionResolution.UNKNOWN,
            "raw_findings": [
                {
                    "security_property": "ROOT_ACCESS",
                    "resolution": "UNKNOWN",
                    "root_cause_id": f"RC_UNK_{i}",
                    "language": lang,
                }
            ],
        })

    # 4. 180 CONFLICT fixtures
    for i in range(180):
        lang = LANGUAGES[i % len(LANGUAGES)]
        fixtures.append({
            "id": f"D6_FIX_CONF_{i:04d}",
            "language": lang,
            "expected_resolution": DecisionResolution.CONFLICT,
            "raw_findings": [
                {
                    "security_property": "TENANT_ESCAPE",
                    "resolution": "SAFE",
                    "root_cause_id": f"RC_CONF_{i}",
                    "language": lang,
                },
                {
                    "security_property": "TENANT_ESCAPE",
                    "resolution": "VULNERABLE",
                    "root_cause_id": f"RC_CONF_{i}",
                    "language": lang,
                },
            ],
        })

    # 5. 180 duplicate / consolidation fixtures
    for i in range(180):
        lang = LANGUAGES[i % len(LANGUAGES)]
        fixtures.append({
            "id": f"D6_FIX_CONSOLIDATE_{i:04d}",
            "language": lang,
            "expected_resolution": DecisionResolution.VULNERABLE,
            "is_consolidation": True,
            "raw_findings": [
                {
                    "security_property": "ADMIN_ACCESS",
                    "resolution": "VULNERABLE",
                    "root_cause_id": f"RC_SHARED_{i}",
                    "language": lang,
                },
                {
                    "security_property": "CLOUD_ADMIN",
                    "resolution": "VULNERABLE",
                    "root_cause_id": f"RC_SHARED_{i}",
                    "language": lang,
                },
            ],
        })

    # 6. 120 boundary / adversarial fixtures
    for i in range(120):
        lang = LANGUAGES[i % len(LANGUAGES)]
        fixtures.append({
            "id": f"D6_FIX_ADV_{i:04d}",
            "language": lang,
            "expected_resolution": DecisionResolution.UNKNOWN if i % 2 == 0 else DecisionResolution.VULNERABLE,
            "raw_findings": [
                {
                    "security_property": "CODE_EXECUTION",
                    "resolution": "VULNERABLE" if i % 2 != 0 else "UNKNOWN",
                    "missing_evidence": i % 2 == 0,
                    "root_cause_id": f"RC_ADV_{i}",
                    "language": lang,
                }
            ],
        })

    return fixtures


D6_FIXTURES = _generate_d6_fixtures()


def test_batch_d6_golden_corpus_fixture_count() -> None:
    """Verifies golden corpus size is exactly 1,200 fixtures."""
    assert len(D6_FIXTURES) == 1200


@pytest.mark.parametrize("fix", D6_FIXTURES, ids=lambda f: f["id"])
def test_batch_d6_golden_corpus_qualification(fix: dict[str, Any]) -> None:
    """Executes qualification evaluation for each D6 fixture."""
    engine = SecurityDecisionEngine()
    graph = engine.analyze(raw_findings=fix["raw_findings"])

    if fix.get("is_consolidation"):
        assert len(graph.findings) == 1
        assert graph.findings[0].resolution == fix["expected_resolution"]
    else:
        assert len(graph.findings) >= 1
        assert graph.findings[0].resolution == fix["expected_resolution"]
