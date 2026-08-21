"""Session Management Reasoning Engine for Batch B3."""

from __future__ import annotations

from karsasec.analysis.session.lifecycle import SessionLifecycleManager
from karsasec.analysis.session.models import (
    CookieAttributes,
    SessionEvidence,
    SessionState,
    SessionSubject,
    SessionToken,
    SessionVulnerabilityType,
)


class SessionReasoningEngine:
    """Deterministic reasoning engine for session management vulnerabilities."""

    def __init__(self) -> None:
        self.lifecycle = SessionLifecycleManager()

    def evaluate_session_fixation(
        self,
        subject: SessionSubject,
        pre_auth_session_id: str,
        post_auth_session_id: str,
        transition: str = "PASSWORD_VERIFIED",
        evidence_path: list[str] | None = None,
    ) -> SessionEvidence | None:
        """B3.1: Detects session fixation where pre-auth session ID is retained post-authentication."""
        path = evidence_path or [f"pre_auth={pre_auth_session_id}", f"post_auth={post_auth_session_id}"]
        if pre_auth_session_id == post_auth_session_id:
            return SessionEvidence(
                category=SessionVulnerabilityType.SESSION_FIXATION,
                subject_id=subject.subject_id,
                session_id=post_auth_session_id,
                pre_auth_state=pre_auth_session_id,
                post_auth_state=post_auth_session_id,
                rotation_required=True,
                rotation_observed=False,
                authentication_transition=transition,
                evidence_path=path,
                resolution="VULNERABLE",
            )
        return None

    def evaluate_session_rotation(
        self,
        subject: SessionSubject,
        old_token: SessionToken,
        new_token: SessionToken,
        transition: str = "PRIVILEGE_ESCALATION",
    ) -> SessionEvidence | None:
        """B3.2: Detects missing session rotation on sensitive state transitions."""
        if not self.lifecycle.verify_session_rotation(subject, old_token, new_token):
            return SessionEvidence(
                category=SessionVulnerabilityType.MISSING_SESSION_ROTATION,
                subject_id=subject.subject_id,
                session_id=old_token.token_id,
                pre_auth_state="ACTIVE",
                post_auth_state="ACTIVE_UNROTATED",
                rotation_required=True,
                rotation_observed=False,
                authentication_transition=transition,
                evidence_path=[f"token_id={old_token.token_id}"],
                resolution="VULNERABLE",
            )
        return None

    def evaluate_logout_invalidation(
        self,
        subject: SessionSubject,
        token: SessionToken,
        is_server_side_invalidated: bool,
    ) -> SessionEvidence | None:
        """B3.8: Detects session retainment post-logout without server-side invalidation."""
        if not is_server_side_invalidated or not token.is_revoked:
            return SessionEvidence(
                category=SessionVulnerabilityType.SESSION_NOT_INVALIDATED_ON_LOGOUT,
                subject_id=subject.subject_id,
                session_id=token.token_id,
                pre_auth_state="ACTIVE",
                post_auth_state="LOGGED_OUT_ACTIVE",
                rotation_required=False,
                rotation_observed=False,
                authentication_transition="LOGOUT",
                evidence_path=[f"session={token.token_id}", "logout()", "server_invalidation=False"],
                resolution="VULNERABLE",
            )
        return None

    def evaluate_cookie_security(self, cookie: CookieAttributes) -> SessionEvidence | None:
        """B3.4-B3.7: Evaluates cookie security attributes (Secure, HttpOnly, SameSite)."""
        if not cookie.is_auth_sensitive:
            return None

        # SameSite=None without Secure is critical vulnerability
        if cookie.samesite == "None" and not cookie.is_secure:
            return SessionEvidence(
                category=SessionVulnerabilityType.INSECURE_COOKIE_ATTRIBUTES,
                subject_id="client",
                session_id=cookie.name,
                pre_auth_state="COOKIE_SET",
                post_auth_state="INSECURE_FLAGS",
                rotation_required=False,
                rotation_observed=False,
                authentication_transition="SET_COOKIE",
                evidence_path=[f"cookie={cookie.name}", "SameSite=None", "Secure=False"],
                resolution="VULNERABLE",
            )

        if not cookie.is_secure or not cookie.is_httponly or cookie.samesite in ("Missing", "Unknown"):
            missing_flags = []
            if not cookie.is_secure:
                missing_flags.append("Secure")
            if not cookie.is_httponly:
                missing_flags.append("HttpOnly")
            if cookie.samesite in ("Missing", "Unknown"):
                missing_flags.append("SameSite")

            return SessionEvidence(
                category=SessionVulnerabilityType.INSECURE_COOKIE_ATTRIBUTES,
                subject_id="client",
                session_id=cookie.name,
                pre_auth_state="COOKIE_SET",
                post_auth_state="INSECURE_FLAGS",
                rotation_required=False,
                rotation_observed=False,
                authentication_transition="SET_COOKIE",
                evidence_path=[f"cookie={cookie.name}", f"missing={','.join(missing_flags)}"],
                resolution="VULNERABLE",
            )
        return None

    def evaluate_token_in_url(self, param_name: str, flows_to_url: bool) -> SessionEvidence | None:
        """B3.13: Detects sensitive security tokens passed in URL parameters."""
        sensitive_tokens = {"session", "token", "access_token", "refresh_token", "reset_token"}
        if param_name.lower() in sensitive_tokens and flows_to_url:
            return SessionEvidence(
                category=SessionVulnerabilityType.TOKEN_IN_URL,
                subject_id="user",
                session_id=param_name,
                pre_auth_state="TOKEN_ISSUED",
                post_auth_state="EXPOSED_IN_URL",
                rotation_required=False,
                rotation_observed=False,
                authentication_transition="URL_TRANSPORT",
                evidence_path=[f"param={param_name}", "url_flow=True"],
                resolution="VULNERABLE",
            )
        return None

    def evaluate_refresh_token_reuse(self, token: SessionToken, reuse_count: int) -> SessionEvidence | None:
        """B3.9: Detects refresh token replay when a revoked/rotated refresh token is reused."""
        if (token.is_rotated or token.is_revoked) and reuse_count > 1:
            return SessionEvidence(
                category=SessionVulnerabilityType.REFRESH_TOKEN_REUSE,
                subject_id="client",
                session_id=token.token_id,
                pre_auth_state="ROTATED",
                post_auth_state="REUSED",
                rotation_required=True,
                rotation_observed=False,
                authentication_transition="REFRESH_GRANT",
                evidence_path=[f"refresh_token={token.token_id}", f"reuse_count={reuse_count}"],
                resolution="VULNERABLE",
            )
        return None

    def evaluate_authn_session_authz_correlation(
        self,
        mfa_completed: bool,
        session_state: SessionState,
        is_authorized: bool,
    ) -> SessionEvidence | None:
        """Section 15: Connects Authentication -> Session -> Authorization state transitions."""
        if session_state == SessionState.REVOKED and is_authorized:
            return SessionEvidence(
                category=SessionVulnerabilityType.CONCURRENT_SESSION_ABUSE,
                subject_id="revoked_user",
                session_id="revoked_session",
                pre_auth_state="REVOKED",
                post_auth_state="AUTHORIZED",
                rotation_required=False,
                rotation_observed=False,
                authentication_transition="REVOKED_ACCESS",
                evidence_path=["session_revoked=True", "authorization_granted=True"],
                resolution="VULNERABLE",
            )
        return None
