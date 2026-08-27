"""Language-Native Patch Parity Unit Tests.

Ensures that patch proposals match the target file extension language 
and do not emit cross-language hallucinated APIs (e.g. Python cursor.execute in PHP files).
"""

import pytest
from karsasec.ai.remediation.models import RemediationStrategy, RemediationStrategyType
from karsasec.ai.remediation.provider import TemplatePatchProvider
from karsasec.ai.rca.models import RootCauseCategory


@pytest.mark.parametrize(
    "file_path, expected_api_token, forbidden_api_token",
    [
        ("app/db.php", "mysqli_prepare", "cursor.execute"),
        ("app/db.php", "mysqli_stmt_bind_param", "cursor.execute"),
        ("services/user.py", "cursor.execute", "mysqli_prepare"),
        ("src/db.js", "db.query", "mysqli_prepare"),
        ("main.go", "db.Query", "cursor.execute"),
        ("Dao.java", "PreparedStatement", "mysqli_prepare"),
        ("Service.cs", "Parameters.AddWithValue", "cursor.execute"),
    ],
)
def test_language_native_api_parity(
    file_path: str, expected_api_token: str, forbidden_api_token: str
) -> None:
    """Verifies that generated patch text uses the correct language-native API."""
    provider = TemplatePatchProvider()
    strategy = RemediationStrategy(
        finding_id="F-PARITY-TEST",
        root_cause_category=RootCauseCategory.MISSING_SANITIZATION,
        strategy_type=RemediationStrategyType.ADD_PARAMETERIZATION,
        rationale="Parameterize query for target file language",
        target_file=file_path,
        target_locations=(f"{file_path}:10",),
        affected_symbols=("$id",),
        evidence_references=(f"{file_path}:10",),
        knowledge_references=(),
        confidence=1.0,
        assumptions=(),
        limitations=(),
        strategy_fingerprint="fp_parity_test",
    )

    hunks = provider.generate_hunks(
        strategy=strategy,
        original_source="query_line = unsafe_call()",
        start_line=1,
    )

    assert len(hunks) == 1
    proposed_text = hunks[0].proposed_text

    # Language parity assertions
    assert expected_api_token in proposed_text, (
        f"Language parity failure for {file_path}: expected '{expected_api_token}' in proposed patch:\n{proposed_text}"
    )
    assert forbidden_api_token not in proposed_text, (
        f"Cross-language API hallucination for {file_path}: found forbidden '{forbidden_api_token}' in patch:\n{proposed_text}"
    )
