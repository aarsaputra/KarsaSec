"""Canonical K1 Property Registry (Task K1.4).

Provides a unified, declarative registry mapping all 22 K1 security properties
across JWT, OAuth, and Business Logic knowledge packs to their corresponding
rule IDs, pack identifiers, severities, descriptions, safe counterparts, and fixture IDs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from karsasec.rules.patterns.k1.business_logic_rules import K1_BUSINESS_LOGIC_RULES
from karsasec.rules.patterns.k1.jwt_rules import K1_JWT_RULES
from karsasec.rules.patterns.k1.oauth_rules import K1_OAUTH_RULES


@dataclass(frozen=True)
class K1PropertySpec:
    property_id: str
    rule_id: str
    knowledge_pack: str
    severity: str
    cwe: str
    description: str
    safe_counterpart: str
    fixture_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "property_id": self.property_id,
            "rule_id": self.rule_id,
            "knowledge_pack": self.knowledge_pack,
            "severity": self.severity,
            "cwe": self.cwe,
            "description": self.description,
            "safe_counterpart": self.safe_counterpart,
            "fixture_ids": self.fixture_ids,
        }


K1_CANONICAL_PROPERTIES: list[K1PropertySpec] = [
    # --- JWT KNOWLEDGE PACK (8 Rules) ---
    K1PropertySpec("JWT_UNVERIFIED_SIGNATURE", "K1-JWT-001", "JWT", "HIGH", "CWE-347", "JWT signature verification missing or skipped.", "JWT_VERIFICATION", ["k1-jwt-002"]),
    K1PropertySpec("JWT_NONE_ALG", "K1-JWT-002", "JWT", "CRITICAL", "CWE-327", "JWT accepts 'none' algorithm.", "JWT_VERIFICATION", ["k1-jwt-004"]),
    K1PropertySpec("JWT_ALG_CONFUSION", "K1-JWT-003", "JWT", "HIGH", "CWE-327", "JWT algorithm confusion attack vector.", "JWT_VERIFICATION", ["k1-jwt-003"]),
    K1PropertySpec("JWT_WEAK_ALG", "K1-JWT-004", "JWT", "MEDIUM", "CWE-326", "JWT weak symmetric secret key.", "JWT_VERIFICATION", ["k1-jwt-005"]),
    K1PropertySpec("JWT_EXPIRED", "K1-JWT-005", "JWT", "MEDIUM", "CWE-613", "JWT expiration validation disabled.", "JWT_VERIFICATION", ["k1-jwt-007"]),
    K1PropertySpec("JWT_ISSUER", "K1-JWT-006", "JWT", "LOW", "CWE-287", "JWT issuer claim validation disabled.", "JWT_VERIFICATION", ["k1-jwt-009"]),
    K1PropertySpec("JWT_KEY_CONFUSION", "K1-JWT-007", "JWT", "HIGH", "CWE-327", "JWT key confusion vulnerability.", "JWT_VERIFICATION", ["k1-jwt-011"]),
    K1PropertySpec("JWT_UNTRUSTED_SOURCE", "K1-JWT-008", "JWT", "HIGH", "CWE-345", "JWT decoded from untrusted header parameter.", "JWT_VERIFICATION", ["k1-jwt-013"]),

    # --- OAUTH KNOWLEDGE PACK (6 Rules) ---
    K1PropertySpec("OAUTH_REDIRECT_URI", "K1-OAUTH-001", "OAuth", "HIGH", "CWE-601", "Unvalidated/attacker-controlled OAuth redirect URI.", "OAUTH_REDIRECT_URI", ["k1-oauth-001"]),
    K1PropertySpec("OAUTH_MISSING_STATE", "K1-OAUTH-002", "OAuth", "HIGH", "CWE-352", "Missing OAuth CSRF state parameter validation.", "OAUTH_STATE_VALIDATION", ["k1-oauth-003"]),
    K1PropertySpec("OAUTH_MISSING_PKCE", "K1-OAUTH-003", "OAuth", "MEDIUM", "CWE-287", "Authorization code flow without PKCE code challenge.", "OAUTH_PKCE", ["k1-oauth-005"]),
    K1PropertySpec("OAUTH_CODE_REUSE", "K1-OAUTH-004", "OAuth", "HIGH", "CWE-294", "Authorization code reused without single-use invalidation.", "OAUTH_CODE_REUSE", ["k1-oauth-007"]),
    K1PropertySpec("OAUTH_TOKEN_LEAKAGE", "K1-OAUTH-005", "OAuth", "HIGH", "CWE-200", "Access token exposed in URL query string parameter.", "OAUTH_TOKEN_LEAKAGE", ["k1-oauth-008"]),
    K1PropertySpec("OAUTH_SCOPE_ESCALATION", "K1-OAUTH-006", "OAuth", "HIGH", "CWE-269", "Unvalidated requested scope used in token issuance.", "OAUTH_SCOPE_ESCALATION", ["k1-oauth-010"]),

    # --- BUSINESS LOGIC KNOWLEDGE PACK (8 Rules) ---
    K1PropertySpec("MISSING_AUTHZ", "K1-BIZ-001", "Business Logic", "HIGH", "CWE-862", "Sensitive operation missing permission check.", "ENFORCED_AUTHZ", ["k1-biz-001"]),
    K1PropertySpec("IDOR_HORIZONTAL", "K1-BIZ-002", "Business Logic", "HIGH", "CWE-639", "Horizontal IDOR missing owner_id constraint.", "IDOR_HORIZONTAL", ["k1-biz-003"]),
    K1PropertySpec("IDOR_VERTICAL", "K1-BIZ-003", "Business Logic", "HIGH", "CWE-269", "Vertical IDOR missing super_admin check.", "IDOR_VERTICAL", ["k1-biz-005"]),
    K1PropertySpec("WORKFLOW_BYPASS", "K1-BIZ-004", "Business Logic", "HIGH", "CWE-841", "State transition missing workflow precondition check.", "WORKFLOW_BYPASS", ["k1-biz-007"]),
    K1PropertySpec("RACE_AUTHZ", "K1-BIZ-005", "Business Logic", "HIGH", "CWE-362", "Financial balance mutation missing pessimistic row lock.", "RACE_AUTHZ", ["k1-biz-009"]),
    K1PropertySpec("QUANTITY_MANIPULATION", "K1-BIZ-006", "Business Logic", "HIGH", "CWE-20", "Order quantity missing non-positive bounds check.", "QUANTITY_MANIPULATION", ["k1-biz-011"]),
    K1PropertySpec("PRICE_MANIPULATION", "K1-BIZ-007", "Business Logic", "HIGH", "CWE-20", "Price accepted directly from client body.", "PRICE_MANIPULATION", ["k1-biz-013"]),
    K1PropertySpec("INVARIANT_BYPASS", "K1-BIZ-008", "Business Logic", "HIGH", "CWE-840", "Discount application missing single-use is_used check.", "INVARIANT_BYPASS", ["k1-biz-015"]),
]


def get_all_k1_rules() -> list[dict[str, Any]]:
    """Returns combined declarative rules from JWT, OAuth, and Business Logic packs."""
    return list(K1_JWT_RULES) + list(K1_OAUTH_RULES) + list(K1_BUSINESS_LOGIC_RULES)
