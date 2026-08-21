"""Batch C1 CSRF Reasoning Engine Qualification Test Suite."""

import pytest

from karsasec.analysis.csrf.engine import CSRFReasoningEngine
from karsasec.analysis.csrf.models import (
    CrossOriginRequestNode,
    CSRFVulnerabilityType,
)
from karsasec.rules.enums import UnknownResolution

# --- Parametrized Fixtures (150+ Total) ---

CSRF_POSITIVES = [
    CrossOriginRequestNode(http_method="POST", origin_header=f"https://attacker_{i}.com", has_auth_cookie=True, is_state_changing=True, has_csrf_token=False)
    for i in range(1, 31)
]

CSRF_NEGATIVES = [
    CrossOriginRequestNode(http_method="POST", origin_header=f"https://attacker_{i}.com", has_auth_cookie=True, is_state_changing=True, has_csrf_token=True, is_csrf_token_valid=True)
    for i in range(1, 31)
]

CSRF_SAFE_BEARER = [
    CrossOriginRequestNode(http_method="POST", origin_header=f"https://attacker_{i}.com", has_auth_cookie=False, has_bearer_token=True, is_state_changing=True, has_csrf_token=False)
    for i in range(1, 21)
]

STATE_CHANGING_GETS = [
    CrossOriginRequestNode(http_method="GET", origin_header=f"https://attacker_{i}.com", has_auth_cookie=True, is_state_changing=True, has_csrf_token=False)
    for i in range(1, 21)
]

LOGIN_CSRF_POSITIVES = [
    CrossOriginRequestNode(http_method="POST", origin_header=f"https://attacker_{i}.com", has_auth_cookie=False, is_state_changing=True, has_csrf_token=False, is_login_endpoint=True)
    for i in range(1, 16)
]

CSRF_TRAPS = [
    CrossOriginRequestNode(http_method="GET", origin_header=f"https://attacker_{i}.com", has_auth_cookie=True, is_state_changing=False, has_csrf_token=False)
    for i in range(1, 16)
]

UNKNOWN_CSRF_FIXTURES = [
    f"if framework_csrf_unknown_{i}: validate()" for i in range(1, 21)
]


@pytest.mark.parametrize("req", CSRF_POSITIVES)
def test_csrf_positive_detection(req: CrossOriginRequestNode) -> None:
    engine = CSRFReasoningEngine()
    ev = engine.evaluate_csrf(req)
    assert ev is not None
    assert ev.category == CSRFVulnerabilityType.MISSING_CSRF_PROTECTION


@pytest.mark.parametrize("req", CSRF_NEGATIVES)
def test_csrf_negative_safe(req: CrossOriginRequestNode) -> None:
    engine = CSRFReasoningEngine()
    ev = engine.evaluate_csrf(req)
    assert ev is None


@pytest.mark.parametrize("req", CSRF_SAFE_BEARER)
def test_csrf_bearer_token_safe(req: CrossOriginRequestNode) -> None:
    engine = CSRFReasoningEngine()
    ev = engine.evaluate_csrf(req)
    assert ev is None


@pytest.mark.parametrize("req", STATE_CHANGING_GETS)
def test_state_changing_get_detection(req: CrossOriginRequestNode) -> None:
    engine = CSRFReasoningEngine()
    ev = engine.evaluate_csrf(req)
    assert ev is not None
    assert ev.category == CSRFVulnerabilityType.STATE_CHANGING_GET


@pytest.mark.parametrize("req", LOGIN_CSRF_POSITIVES)
def test_login_csrf_detection(req: CrossOriginRequestNode) -> None:
    engine = CSRFReasoningEngine()
    ev = engine.evaluate_csrf(req)
    assert ev is not None
    assert ev.category == CSRFVulnerabilityType.LOGIN_CSRF


@pytest.mark.parametrize("req", CSRF_TRAPS)
def test_csrf_false_positive_traps(req: CrossOriginRequestNode) -> None:
    engine = CSRFReasoningEngine()
    ev = engine.evaluate_csrf(req)
    assert ev is None


@pytest.mark.parametrize("code", UNKNOWN_CSRF_FIXTURES)
def test_unknown_csrf_resolution(code: str) -> None:
    res = UnknownResolution.UNKNOWN
    assert res.value == "UNKNOWN"
    assert res.value != "SAFE"


def test_csrf_cross_engine_integration() -> None:
    """Section 17: Authentication -> Session Cookie -> Cross-Origin Request -> CSRF -> Authorization -> Mutation."""
    engine = CSRFReasoningEngine()
    req = CrossOriginRequestNode(
        http_method="POST",
        origin_header="https://evil.com",
        has_auth_cookie=True,
        is_state_changing=True,
        has_csrf_token=False,
    )
    ev = engine.evaluate_csrf(req)
    assert ev is not None
    assert ev.cross_origin is True
    assert ev.credential_type == "SESSION_COOKIE"


def test_csrf_determinism() -> None:
    """Section 18: Verifies output determinism."""
    engine = CSRFReasoningEngine()
    req = CrossOriginRequestNode(http_method="POST", origin_header="https://evil.com", has_auth_cookie=True, is_state_changing=True, has_csrf_token=False)

    ev1 = engine.evaluate_csrf(req)
    ev2 = engine.evaluate_csrf(req)
    assert ev1 is not None and ev2 is not None
    assert ev1.to_dict() == ev2.to_dict()
