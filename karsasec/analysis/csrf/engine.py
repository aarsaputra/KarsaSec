"""CSRF Security Reasoning Engine for Batch C1."""

from __future__ import annotations

from karsasec.analysis.csrf.models import (
    CrossOriginRequestNode,
    CSRFEvidence,
    CSRFVulnerabilityType,
)


class CSRFReasoningEngine:
    """Deterministic reasoning engine for Cross-Site Request Forgery vulnerabilities."""

    STATE_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

    def evaluate_csrf(self, request: CrossOriginRequestNode) -> CSRFEvidence | None:
        """Evaluates CSRF security over cross-site request triples."""
        # Bearer tokens (Authorization: Bearer xyz) do NOT automatically attach on cross-site browser requests
        if request.has_bearer_token and not request.has_auth_cookie:
            return None

        # C1.6: State-Changing GET
        if request.http_method == "GET" and request.is_state_changing:
            return CSRFEvidence(
                category=CSRFVulnerabilityType.STATE_CHANGING_GET,
                origin=request.origin_header or "CROSS_ORIGIN",
                cross_origin=True,
                credential_type="SESSION_COOKIE" if request.has_auth_cookie else "NONE",
                state_changing=True,
                csrf_protection=request.has_csrf_token,
                authorization_required=True,
                evidence_path=["http_method=GET", "state_changing=True", "mutation_observed=True"],
                resolution="VULNERABLE",
            )

        # C1.5: Login CSRF
        if request.is_login_endpoint and not request.has_csrf_token:
            return CSRFEvidence(
                category=CSRFVulnerabilityType.LOGIN_CSRF,
                origin=request.origin_header or "CROSS_ORIGIN",
                cross_origin=True,
                credential_type="LOGIN_CREDENTIALS",
                state_changing=True,
                csrf_protection=False,
                authorization_required=False,
                evidence_path=["endpoint=login", "cross_origin_submission=True", "csrf_token=Missing"],
                resolution="VULNERABLE",
            )

        # C1.1: Missing CSRF Protection on State-Changing Operation
        if request.http_method in self.STATE_MUTATING_METHODS and request.is_state_changing:
            if request.has_auth_cookie and (not request.has_csrf_token or not request.is_csrf_token_valid):
                return CSRFEvidence(
                    category=CSRFVulnerabilityType.MISSING_CSRF_PROTECTION,
                    origin=request.origin_header or "CROSS_ORIGIN",
                    cross_origin=True,
                    credential_type="SESSION_COOKIE",
                    state_changing=True,
                    csrf_protection=False,
                    authorization_required=True,
                    evidence_path=[f"method={request.http_method}", "auth_cookie=True", "csrf_token=Missing_or_Invalid"],
                    resolution="VULNERABLE",
                )

        return None
