"""CORS Security Reasoning Engine for Batch C1."""

from __future__ import annotations

from karsasec.analysis.csrf.models import (
    CORSHeaderNode,
    CSRFEvidence,
    CSRFVulnerabilityType,
)


class CORSReasoningEngine:
    """Deterministic reasoning engine for Cross-Origin Resource Sharing misconfigurations."""

    def evaluate_cors(self, cors_node: CORSHeaderNode) -> CSRFEvidence | None:
        """Evaluates CORS header configuration against credential boundaries."""
        # C1.10: CORS Wildcard with Credentials
        if cors_node.allow_origin == "*" and cors_node.allow_credentials:
            return CSRFEvidence(
                category=CSRFVulnerabilityType.CORS_WILDCARD_WITH_CREDENTIALS,
                origin="*",
                cross_origin=True,
                credential_type="SESSION_COOKIE_OR_BEARER",
                state_changing=False,
                csrf_protection=False,
                authorization_required=True,
                evidence_path=["Access-Control-Allow-Origin=*", "Access-Control-Allow-Credentials=true"],
                resolution="VULNERABLE",
            )

        # C1.13: Arbitrary Origin Reflection without Validation
        if cors_node.is_reflected_origin and cors_node.allow_credentials and not cors_node.is_validated_origin:
            return CSRFEvidence(
                category=CSRFVulnerabilityType.CORS_ORIGIN_REFLECTION,
                origin="REFLECTED_UNTRUSTED",
                cross_origin=True,
                credential_type="SESSION_COOKIE",
                state_changing=False,
                csrf_protection=False,
                authorization_required=True,
                evidence_path=["origin_reflection=True", "allow_credentials=True", "origin_validated=False"],
                resolution="VULNERABLE",
            )

        return None

    def evaluate_origin_validation_pattern(self, pattern_type: str) -> CSRFEvidence | None:
        """C1.8: Evaluates weak origin validation patterns (endswith, startswith, substring)."""
        weak_patterns = {"endswith", "startswith", "substring", "regex_partial"}
        if pattern_type in weak_patterns:
            return CSRFEvidence(
                category=CSRFVulnerabilityType.ORIGIN_VALIDATION_BYPASS,
                origin="WEAK_VALIDATION_MATCH",
                cross_origin=True,
                credential_type="SESSION_COOKIE",
                state_changing=False,
                csrf_protection=False,
                authorization_required=True,
                evidence_path=[f"validation_pattern={pattern_type}", "bypassable_by_subdomain_or_suffix=True"],
                resolution="VULNERABLE",
            )
        return None
