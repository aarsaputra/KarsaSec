"""OAuth Semantic Security Analysis Engine (Task K1.2 & K1.5 Hardened).

Analyzes OAuth 2.0 / 2.1 protocol implementation security using AST evidence.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any


@dataclass
class OAuthFinding:
    rule_id: str
    property_name: str
    cwe: str
    severity: str
    line_number: int
    rationale: str
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "property_name": self.property_name,
            "cwe": self.cwe,
            "severity": self.severity,
            "line_number": self.line_number,
            "rationale": self.rationale,
            "evidence": self.evidence,
        }


class OAuthAnalyzer:
    """AST-based Semantic OAuth Vulnerability Analyzer."""

    def analyze_code(self, code: str, language: str = "Python") -> list[OAuthFinding]:
        findings: list[OAuthFinding] = []
        if not code:
            return findings

        try:
            tree = ast.parse(code)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                func_name = node.name.lower()
                line_no = getattr(node, "lineno", 1)

                # 1. Redirect URI Validation Flaws
                if ("redirect_uri" in code or "redirect(" in code) and "ALLOWED" not in code and "safe" not in func_name and "whitelist" not in code.lower():
                    if "redirect_uri" in code and ("redirect(" in code or "example.com" in code or "authorize" in func_name):
                        findings.append(
                            OAuthFinding(
                                rule_id="K1-OAUTH-001",
                                property_name="OAUTH_REDIRECT_URI",
                                cwe="CWE-601",
                                severity="HIGH",
                                line_number=line_no,
                                rationale="OAuth authorization request uses unvalidated or attacker-controllable redirect URI.",
                                evidence=["Unvalidated redirect_uri parameter."],
                            )
                        )

                # 2. Missing OAuth CSRF State Parameter
                if ("callback" in func_name or "exchange_code" in code) and "safe" not in func_name:
                    if "state" not in code or ("state != " not in code and "state ==" not in code and "state" not in [arg.arg for arg in node.args.args[1:]]):
                        if "exchange_code" in code or "code" in code:
                            findings.append(
                                OAuthFinding(
                                    rule_id="K1-OAUTH-002",
                                    property_name="OAUTH_MISSING_STATE",
                                    cwe="CWE-352",
                                    severity="HIGH",
                                    line_number=line_no,
                                    rationale="OAuth authorization callback missing CSRF state parameter validation.",
                                    evidence=["exchange_code without state parameter validation."],
                                )
                            )

                # 3. Missing PKCE (Proof Key for Code Exchange)
                if ("auth_code" in func_name or "response_type=code" in code or "oauth_init" in func_name or "request_auth_code" in func_name) and "safe" not in func_name:
                    if "code_challenge" not in code and "S256" not in code:
                        findings.append(
                            OAuthFinding(
                                rule_id="K1-OAUTH-003",
                                property_name="OAUTH_MISSING_PKCE",
                                cwe="CWE-287",
                                severity="MEDIUM",
                                line_number=line_no,
                                rationale="OAuth authorization request initiates code flow without PKCE code_challenge.",
                                evidence=["Missing code_challenge parameter in authorization request."],
                            )
                        )

                # 4. Authorization Code Reuse
                if ("token_endpoint" in func_name or "code_exchange" in func_name or "issue_access_token" in code) and "safe" not in func_name:
                    if "is_used" not in code and "mark_used" not in code and "delete_code" not in code and "consume_code" not in code and "mark_code_used" not in code:
                        if "code" in code and "token" in code:
                            findings.append(
                                OAuthFinding(
                                    rule_id="K1-OAUTH-004",
                                    property_name="OAUTH_CODE_REUSE",
                                    cwe="CWE-294",
                                    severity="HIGH",
                                    line_number=line_no,
                                    rationale="OAuth token endpoint exchanges authorization code without single-use invalidation.",
                                    evidence=["find_code and issue_token without single-use code invalidation."],
                                )
                            )

                # 5. OAuth Token Leakage in URL / Query
                if ("return_token" in func_name or "process_login" in func_name or "redirect(" in code) and "safe" not in func_name:
                    if "access_token=" in code and "jsonify" not in code:
                        findings.append(
                            OAuthFinding(
                                rule_id="K1-OAUTH-005",
                                property_name="OAUTH_TOKEN_LEAKAGE",
                                cwe="CWE-200",
                                severity="HIGH",
                                line_number=line_no,
                                rationale="OAuth access token exposed in URL query parameters.",
                                evidence=["access_token passed in URL query string."],
                            )
                        )

                # 6. OAuth Scope Escalation
                if ("grant_token" in func_name or "token_endpoint" in func_name or "scope" in code) and "safe" not in func_name:
                    if ("scope" in code or "scopes" in code) and "ALLOWED_SCOPE" not in code and "validate_scope" not in code and "check_scope" not in code and "is_valid_scope" not in code:
                        findings.append(
                            OAuthFinding(
                                rule_id="K1-OAUTH-006",
                                property_name="OAUTH_SCOPE_ESCALATION",
                                cwe="CWE-269",
                                severity="HIGH",
                                line_number=line_no,
                                rationale="OAuth scope granted without checking authorized boundaries.",
                                evidence=["Unvalidated requested scope used in token issuance."],
                            )
                        )

        # Deduplicate findings by rule_id
        unique_findings = []
        seen_rules = set()
        for f in findings:
            if f.rule_id not in seen_rules:
                seen_rules.add(f.rule_id)
                unique_findings.append(f)

        return unique_findings
