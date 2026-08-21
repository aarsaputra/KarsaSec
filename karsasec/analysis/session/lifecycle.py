"""Session Lifecycle Manager for tracking state transitions and rotation requirements."""

from __future__ import annotations

from karsasec.analysis.session.models import SessionState, SessionSubject, SessionToken


class SessionLifecycleManager:
    """Manages session state transitions and verifies valid rotation/revocation sequences."""

    VALID_TRANSITIONS: dict[SessionState, set[SessionState]] = {
        SessionState.CREATED: {SessionState.AUTHENTICATED, SessionState.MFA_PENDING, SessionState.REVOKED},
        SessionState.MFA_PENDING: {SessionState.AUTHENTICATED, SessionState.REVOKED, SessionState.EXPIRED},
        SessionState.AUTHENTICATED: {SessionState.ACTIVE, SessionState.ROTATING, SessionState.REVOKED},
        SessionState.ACTIVE: {SessionState.ROTATING, SessionState.LOGGED_OUT, SessionState.EXPIRED, SessionState.REVOKED},
        SessionState.ROTATING: {SessionState.ACTIVE, SessionState.REVOKED},
        SessionState.LOGGED_OUT: {SessionState.REVOKED},
        SessionState.REVOKED: set(),
        SessionState.EXPIRED: {SessionState.REVOKED},
        SessionState.UNKNOWN: {SessionState.UNKNOWN, SessionState.ACTIVE, SessionState.REVOKED},
    }

    def is_valid_transition(self, current: SessionState, target: SessionState) -> bool:
        """Returns True if state transition current -> target is permitted."""
        allowed = self.VALID_TRANSITIONS.get(current, set())
        return target in allowed

    def verify_session_rotation(self, subject: SessionSubject, token_before: SessionToken, token_after: SessionToken) -> bool:
        """Returns True if session identifier was successfully regenerated/rotated during transition."""
        if token_before.token_id == token_after.token_id:
            return False
        return True
