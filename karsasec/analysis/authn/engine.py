"""Authentication Reasoning Engine for Batch B2."""

from __future__ import annotations

from karsasec.analysis.authn.models import (
    AuthnEvidence,
    AuthnVulnerabilityType,
    AuthStateNode,
    ResetTokenNode,
)


class AuthenticationReasoningEngine:
    """Deterministic reasoning engine for authentication vulnerabilities."""

    WEAK_HASH_FUNCTIONS = {"md5", "sha1", "base64", "crypt"}

    def evaluate_credential_hashing(self, hash_algorithm: str, is_salted: bool, location: str) -> AuthnEvidence | None:
        """B2.1: Evaluates password hashing strength."""
        algo_lower = hash_algorithm.lower()
        if algo_lower in self.WEAK_HASH_FUNCTIONS or not is_salted:
            return AuthnEvidence(
                vulnerability_type=AuthnVulnerabilityType.WEAK_CREDENTIAL_HASHING,
                location=location,
                finding="WEAK_CREDENTIAL_HASHING",
                description=f"Insecure hash algorithm '{hash_algorithm}' (salted={is_salted}) used for credential storage.",
            )
        return None

    def evaluate_password_reset(self, token_node: ResetTokenNode, location: str) -> AuthnEvidence | None:
        """B2.2: Evaluates password reset token entropy, binding, single-use, and expiration."""
        reasons = []
        if not token_node.has_entropy:
            reasons.append("predictable token entropy")
        if not token_node.has_expiration:
            reasons.append("missing expiration window")
        if not token_node.is_user_bound:
            reasons.append("unbound to user identity")
        if not token_node.is_single_use:
            reasons.append("token reusable across attempts")

        if reasons:
            return AuthnEvidence(
                vulnerability_type=AuthnVulnerabilityType.INSECURE_PASSWORD_RESET,
                location=location,
                finding="INSECURE_PASSWORD_RESET",
                description="Insecure password reset token flaw: " + ", ".join(reasons),
            )
        return None

    def evaluate_mfa_state_machine(self, auth_state: AuthStateNode, location: str) -> AuthnEvidence | None:
        """B2.3: Detects session token issuance before MFA challenge is completed."""
        if auth_state.mfa_required and not auth_state.mfa_completed and auth_state.session_issued:
            return AuthnEvidence(
                vulnerability_type=AuthnVulnerabilityType.MFA_BYPASS,
                location=location,
                finding="MFA_BYPASS",
                description="Session token issued prior to MFA challenge verification completion.",
            )
        return None

    def evaluate_account_enumeration(self, invalid_user_msg: str, invalid_pass_msg: str, location: str) -> AuthnEvidence | None:
        """B2.4: Detects user enumeration via divergent error messages."""
        if invalid_user_msg != invalid_pass_msg:
            return AuthnEvidence(
                vulnerability_type=AuthnVulnerabilityType.ACCOUNT_ENUMERATION,
                location=location,
                finding="ACCOUNT_ENUMERATION",
                description=f"Divergent authentication error message ('{invalid_user_msg}' vs '{invalid_pass_msg}') exposes user existence.",
            )
        return None

    def evaluate_secret_comparison(self, operator: str, is_constant_time: bool, location: str) -> AuthnEvidence | None:
        """B2.5: Detects timing attack surface when comparing secret tokens with non-constant time operator (==)."""
        if operator == "==" and not is_constant_time:
            return AuthnEvidence(
                vulnerability_type=AuthnVulnerabilityType.TIMING_ATTACK_SURFACE,
                location=location,
                finding="TIMING_ATTACK_SURFACE",
                description="Non-constant-time string comparison (==) on secret token creates timing attack surface. Use hmac.compare_digest().",
            )
        return None
