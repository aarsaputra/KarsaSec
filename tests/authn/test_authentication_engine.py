"""Batch B2 Authentication Reasoning Engine Test Suite."""

from karsasec.analysis.authn.engine import AuthenticationReasoningEngine
from karsasec.analysis.authn.models import (
    AuthnVulnerabilityType,
    AuthStateNode,
    ResetTokenNode,
)


def test_b2_1_weak_credential_hashing() -> None:
    """B2.1: Verifies detection of weak/unsalted hash algorithms (MD5, SHA1)."""
    engine = AuthenticationReasoningEngine()
    ev1 = engine.evaluate_credential_hashing("MD5", is_salted=True, location="auth/user.py:45")
    assert ev1 is not None
    assert ev1.vulnerability_type == AuthnVulnerabilityType.WEAK_CREDENTIAL_HASHING

    ev2 = engine.evaluate_credential_hashing("SHA256", is_salted=False, location="auth/user.py:50")
    assert ev2 is not None
    assert ev2.vulnerability_type == AuthnVulnerabilityType.WEAK_CREDENTIAL_HASHING


def test_b2_2_insecure_password_reset() -> None:
    """B2.2: Verifies detection of insecure password reset tokens."""
    engine = AuthenticationReasoningEngine()
    token = ResetTokenNode(
        token_str="predictable_123",
        has_entropy=False,
        has_expiration=False,
        is_user_bound=False,
        is_single_use=False,
    )
    ev = engine.evaluate_password_reset(token, location="auth/reset.py:22")
    assert ev is not None
    assert ev.vulnerability_type == AuthnVulnerabilityType.INSECURE_PASSWORD_RESET
    assert "predictable token entropy" in ev.description


def test_b2_3_mfa_state_machine_bypass() -> None:
    """B2.3: Verifies detection of MFA state machine bypass (session issued before MFA completion)."""
    engine = AuthenticationReasoningEngine()
    state = AuthStateNode(
        step_name="login",
        password_accepted=True,
        mfa_required=True,
        mfa_completed=False,
        session_issued=True,
    )
    ev = engine.evaluate_mfa_state_machine(state, location="auth/mfa.py:88")
    assert ev is not None
    assert ev.vulnerability_type == AuthnVulnerabilityType.MFA_BYPASS


def test_b2_4_account_enumeration() -> None:
    """B2.4: Verifies detection of user account enumeration via divergent error messages."""
    engine = AuthenticationReasoningEngine()
    ev = engine.evaluate_account_enumeration(
        invalid_user_msg="User not found.",
        invalid_pass_msg="Invalid password for user.",
        location="auth/login.py:60",
    )
    assert ev is not None
    assert ev.vulnerability_type == AuthnVulnerabilityType.ACCOUNT_ENUMERATION


def test_b2_5_timing_attack_surface() -> None:
    """B2.5: Verifies detection of non-constant time comparison on secret tokens."""
    engine = AuthenticationReasoningEngine()
    ev = engine.evaluate_secret_comparison(operator="==", is_constant_time=False, location="auth/verify.py:14")
    assert ev is not None
    assert ev.vulnerability_type == AuthnVulnerabilityType.TIMING_ATTACK_SURFACE


def test_secure_authentication_flow_safe() -> None:
    """Verifies that secure authentication routines return None (SAFE)."""
    engine = AuthenticationReasoningEngine()
    assert engine.evaluate_credential_hashing("Argon2id", is_salted=True, location="loc") is None

    valid_token = ResetTokenNode(token_str="rand_sec_token", has_entropy=True, has_expiration=True, is_user_bound=True, is_single_use=True)
    assert engine.evaluate_password_reset(valid_token, location="loc") is None

    valid_mfa = AuthStateNode(step_name="login", password_accepted=True, mfa_required=True, mfa_completed=True, session_issued=True)
    assert engine.evaluate_mfa_state_machine(valid_mfa, location="loc") is None

    assert engine.evaluate_account_enumeration("Invalid credentials.", "Invalid credentials.", location="loc") is None
    assert engine.evaluate_secret_comparison(operator="==", is_constant_time=True, location="loc") is None
