"""K1 OAuth Knowledge Pack Declarative Rules Definition (Task K1.2)."""

from __future__ import annotations

from typing import Any

K1_OAUTH_RULES: list[dict[str, Any]] = [
    {
        "rule_id": "K1-OAUTH-001",
        "name": "OAuth Insecure Redirect URI Validation",
        "cwe": "CWE-601",
        "property": "OAUTH_REDIRECT_URI",
        "severity": "HIGH",
        "category": "OAUTH",
        "sanitizer_semantics": "NONE",
        "description": "Detects OAuth authorization requests using unvalidated or attacker-controllable redirect URIs.",
    },
    {
        "rule_id": "K1-OAUTH-002",
        "name": "OAuth Missing CSRF State Parameter",
        "cwe": "CWE-352",
        "property": "OAUTH_MISSING_STATE",
        "severity": "HIGH",
        "category": "OAUTH",
        "sanitizer_semantics": "NONE",
        "description": "Detects OAuth authorization callbacks lacking CSRF state parameter validation.",
    },
    {
        "rule_id": "K1-OAUTH-003",
        "name": "OAuth Missing PKCE Protection",
        "cwe": "CWE-287",
        "property": "OAUTH_MISSING_PKCE",
        "severity": "MEDIUM",
        "category": "OAUTH",
        "sanitizer_semantics": "NONE",
        "description": "Detects OAuth authorization requests initiating code flow without PKCE code challenges.",
    },
    {
        "rule_id": "K1-OAUTH-004",
        "name": "OAuth Authorization Code Reuse",
        "cwe": "CWE-294",
        "property": "OAUTH_CODE_REUSE",
        "severity": "HIGH",
        "category": "OAUTH",
        "sanitizer_semantics": "NONE",
        "description": "Detects OAuth token endpoints exchanging authorization codes without single-use invalidation.",
    },
    {
        "rule_id": "K1-OAUTH-005",
        "name": "OAuth Access Token Leakage in URL",
        "cwe": "CWE-200",
        "property": "OAUTH_TOKEN_LEAKAGE",
        "severity": "HIGH",
        "category": "OAUTH",
        "sanitizer_semantics": "NONE",
        "description": "Detects OAuth access tokens exposed in URL query parameters.",
    },
    {
        "rule_id": "K1-OAUTH-006",
        "name": "OAuth Scope Escalation",
        "cwe": "CWE-269",
        "property": "OAUTH_SCOPE_ESCALATION",
        "severity": "HIGH",
        "category": "OAUTH",
        "sanitizer_semantics": "NONE",
        "description": "Detects OAuth token issuance with unvalidated scope parameter.",
    },
]
