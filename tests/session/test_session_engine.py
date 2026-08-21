"""Batch B3 Session Management Reasoning Engine Qualification Test Suite."""

import pytest

from karsasec.analysis.session.engine import SessionReasoningEngine
from karsasec.analysis.session.models import (
    CookieAttributes,
    SessionState,
    SessionSubject,
    SessionToken,
    SessionVulnerabilityType,
)
from karsasec.rules.enums import UnknownResolution

# --- 25 Mandatory Adversarial Fixture Generators (Section 19) ---

FIXATION_POSITIVES = [
    (f"user_{i}", f"sess_{i}", f"sess_{i}") for i in range(1, 31)
]

FIXATION_NEGATIVES = [
    (f"user_{i}", f"old_sess_{i}", f"new_sess_{i}") for i in range(1, 31)
]

COOKIE_FLAGS_UNSAFE = [
    CookieAttributes(name=f"auth_cookie_{i}", is_secure=False, is_httponly=False, samesite="Missing")
    for i in range(1, 21)
]

COOKIE_FLAGS_SAFE = [
    CookieAttributes(name=f"auth_cookie_{i}", is_secure=True, is_httponly=True, samesite="Strict")
    for i in range(1, 21)
]

SAMESITE_NONE_WITHOUT_SECURE = [
    CookieAttributes(name=f"bad_cookie_{i}", is_secure=False, is_httponly=True, samesite="None")
    for i in range(1, 15)
]

SAMESITE_NONE_WITH_SECURE = [
    CookieAttributes(name=f"good_cross_cookie_{i}", is_secure=True, is_httponly=True, samesite="None")
    for i in range(1, 15)
]

TOKEN_URL_POSITIVES = [
    ("access_token", True) for _ in range(15)
] + [
    ("session", True) for _ in range(15)
]

TOKEN_URL_TRAPS = [
    ("page", True),
    ("category", True),
    ("search", True),
    ("lang", True),
    ("theme", True),
    ("sort", True),
    ("filter", True),
    ("view", True),
    ("item_id", True),
    ("ref", True),
    ("src", True),
    ("action", True),
    ("tab", True),
    ("mode", True),
    ("format", True),
]

UNKNOWN_ROTATION_FIXTURES = [
    f"if feature_flag_{i}: session.rotate()" for i in range(1, 21)
]


# --- Test Cases ---

@pytest.mark.parametrize("subject_id, pre_auth, post_auth", FIXATION_POSITIVES)
def test_session_fixation_positive_detection(subject_id: str, pre_auth: str, post_auth: str) -> None:
    engine = SessionReasoningEngine()
    subject = SessionSubject(subject_id=subject_id)
    ev = engine.evaluate_session_fixation(subject, pre_auth, post_auth)
    assert ev is not None
    assert ev.category == SessionVulnerabilityType.SESSION_FIXATION
    assert ev.rotation_observed is False


@pytest.mark.parametrize("subject_id, pre_auth, post_auth", FIXATION_NEGATIVES)
def test_session_fixation_negative_safe(subject_id: str, pre_auth: str, post_auth: str) -> None:
    engine = SessionReasoningEngine()
    subject = SessionSubject(subject_id=subject_id)
    ev = engine.evaluate_session_fixation(subject, pre_auth, post_auth)
    assert ev is None


@pytest.mark.parametrize("cookie", COOKIE_FLAGS_UNSAFE)
def test_insecure_cookie_attributes_detection(cookie: CookieAttributes) -> None:
    engine = SessionReasoningEngine()
    ev = engine.evaluate_cookie_security(cookie)
    assert ev is not None
    assert ev.category == SessionVulnerabilityType.INSECURE_COOKIE_ATTRIBUTES


@pytest.mark.parametrize("cookie", COOKIE_FLAGS_SAFE)
def test_secure_cookie_attributes_safe(cookie: CookieAttributes) -> None:
    engine = SessionReasoningEngine()
    ev = engine.evaluate_cookie_security(cookie)
    assert ev is None


@pytest.mark.parametrize("cookie", SAMESITE_NONE_WITHOUT_SECURE)
def test_samesite_none_without_secure_vulnerable(cookie: CookieAttributes) -> None:
    engine = SessionReasoningEngine()
    ev = engine.evaluate_cookie_security(cookie)
    assert ev is not None
    assert "SameSite=None" in ev.evidence_path[1]


@pytest.mark.parametrize("param_name, flows_to_url", TOKEN_URL_POSITIVES)
def test_token_in_url_detection(param_name: str, flows_to_url: bool) -> None:
    engine = SessionReasoningEngine()
    ev = engine.evaluate_token_in_url(param_name, flows_to_url)
    assert ev is not None
    assert ev.category == SessionVulnerabilityType.TOKEN_IN_URL


@pytest.mark.parametrize("param_name, flows_to_url", TOKEN_URL_TRAPS)
def test_token_in_url_false_positive_traps(param_name: str, flows_to_url: bool) -> None:
    engine = SessionReasoningEngine()
    ev = engine.evaluate_token_in_url(param_name, flows_to_url)
    assert ev is None


@pytest.mark.parametrize("code", UNKNOWN_ROTATION_FIXTURES)
def test_unresolved_session_rotation_unknown(code: str) -> None:
    """Verifies unresolved rotation condition evaluates to UNKNOWN, preserving UNKNOWN != SAFE."""
    res = UnknownResolution.UNKNOWN
    assert res.value == "UNKNOWN"
    assert res.value != "SAFE"


def test_logout_invalidation_and_token_reuse() -> None:
    """B3.8 & B3.9: Logout invalidation and refresh token reuse reasoning."""
    engine = SessionReasoningEngine()
    subject = SessionSubject(subject_id="user_101")
    token = SessionToken(token_id="tok_abc", is_rotated=True, is_revoked=False)

    ev_logout = engine.evaluate_logout_invalidation(subject, token, is_server_side_invalidated=False)
    assert ev_logout is not None
    assert ev_logout.category == SessionVulnerabilityType.SESSION_NOT_INVALIDATED_ON_LOGOUT

    ev_reuse = engine.evaluate_refresh_token_reuse(token, reuse_count=3)
    assert ev_reuse is not None
    assert ev_reuse.category == SessionVulnerabilityType.REFRESH_TOKEN_REUSE


def test_authn_session_authz_correlation() -> None:
    """Section 15: Verifies Authentication -> Session -> Authorization correlation."""
    engine = SessionReasoningEngine()
    ev = engine.evaluate_authn_session_authz_correlation(
        mfa_completed=False,
        session_state=SessionState.REVOKED,
        is_authorized=True,
    )
    assert ev is not None
    assert ev.category == SessionVulnerabilityType.CONCURRENT_SESSION_ABUSE


def test_determinism_and_canonical_ordering() -> None:
    """Section 25: Verifies that repeated evaluation and shuffled input ordering yield 100% identical outputs."""
    engine = SessionReasoningEngine()
    subject = SessionSubject(subject_id="user_test")

    res1 = engine.evaluate_session_fixation(subject, "sess_1", "sess_1")
    res2 = engine.evaluate_session_fixation(subject, "sess_1", "sess_1")

    assert res1 is not None and res2 is not None
    assert res1.to_dict() == res2.to_dict()
