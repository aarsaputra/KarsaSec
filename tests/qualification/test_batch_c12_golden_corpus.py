"""Batch C12 Secrets & Credential Exposure Golden Corpus Qualification Test Suite (200 Fixtures across 7 Languages)."""

import pytest

from karsasec.analysis.secrets.engine import SecretExposureReasoningEngine
from karsasec.analysis.secrets.models import (
    CredentialValidity,
    PrivilegeLevel,
    SecretContext,
    SecretType,
)

LANGUAGES = ["python", "javascript", "php", "java", "go", "ruby", "dotnet"]

# --- 200 High-Quality Parametrized Fixtures (50 TP, 50 TN, 50 UNKNOWN, 50 Edge Cases) ---

EXPOSURE_POSITIVES = [
    SecretContext(
        secret_type=SecretType.AWS_SECRET_KEY if i % 2 == 0 else SecretType.JWT_SIGNING_KEY,
        secret_value=f"secret_val_{i}",
        source_boundary="ENVIRONMENT_VARIABLE",
        exposure_boundary="HTTP_RESPONSE" if i % 2 == 0 else "LOG_FILE",
        is_cross_boundary=True,
        language=LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 51)
]

SAFE_NEGATIVES = [
    SecretContext(
        secret_type=SecretType.AWS_ACCESS_KEY if i % 2 == 0 else SecretType.GENERIC_SECRET,
        secret_value=f"internal_key_{i}",
        source_boundary="SOURCE_CODE",
        exposure_boundary=None,
        is_cross_boundary=False,
        is_vault_managed=True if i % 2 == 0 else False,
        language=LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 51)
]

UNKNOWN_CASES = [
    SecretContext(
        secret_type=SecretType.API_TOKEN,
        secret_value=f"ambiguous_tok_{i}",
        source_boundary="CONFIG_FILE",
        exposure_boundary="AMBIGUOUS_BOUNDARY",
        validity=CredentialValidity.UNKNOWN,
        is_cross_boundary=False,
        language=LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 51)
]

EDGE_CASES_COMPROMISE_AND_ESCALATION = [
    SecretContext(
        secret_type=SecretType.SSH_PRIVATE_KEY if i % 2 == 0 else SecretType.GCP_SERVICE_ACCOUNT,
        secret_value=f"edge_key_{i}",
        source_boundary="METADATA_SERVICE" if i % 2 == 0 else "GIT_REPOSITORY",
        exposure_boundary="PUBLIC_API",
        privilege_level=PrivilegeLevel.ADMIN if i % 2 == 0 else PrivilegeLevel.LIMITED_USER,
        is_cross_boundary=True,
        language=LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 51)
]


@pytest.mark.parametrize("ctx", EXPOSURE_POSITIVES)
def test_exposure_positives(ctx: SecretContext) -> None:
    engine = SecretExposureReasoningEngine()
    ev = engine.evaluate_secret_exposure(ctx)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


@pytest.mark.parametrize("ctx", SAFE_NEGATIVES)
def test_safe_negatives(ctx: SecretContext) -> None:
    engine = SecretExposureReasoningEngine()
    ev = engine.evaluate_secret_exposure(ctx)
    assert ev is not None
    assert ev.resolution == "SAFE"


@pytest.mark.parametrize("ctx", UNKNOWN_CASES)
def test_unknown_cases(ctx: SecretContext) -> None:
    engine = SecretExposureReasoningEngine()
    ev = engine.evaluate_secret_exposure(ctx)
    assert ev is not None
    assert ev.resolution == "UNKNOWN"


@pytest.mark.parametrize("ctx", EDGE_CASES_COMPROMISE_AND_ESCALATION)
def test_edge_cases_compromise_and_escalation(ctx: SecretContext) -> None:
    engine = SecretExposureReasoningEngine()
    ev = engine.evaluate_secret_exposure(ctx)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


def test_c12_determinism() -> None:
    """Section Determinism: Verifies repeated evaluation yields 100% identical outputs."""
    engine = SecretExposureReasoningEngine()
    ctx = SecretContext(
        secret_type=SecretType.AWS_SECRET_KEY,
        secret_value="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        source_boundary="ENVIRONMENT_VARIABLE",
        exposure_boundary="HTTP_RESPONSE",
        is_cross_boundary=True,
    )

    ev1 = engine.evaluate_secret_exposure(ctx)
    ev2 = engine.evaluate_secret_exposure(ctx)
    assert ev1 is not None and ev2 is not None
    assert ev1.to_dict() == ev2.to_dict()
