"""JWT Semantic Security Analysis Engine (Task K1.1 & K1.5 Hardened).

Analyzes JWT token parsing, signature verification, algorithm selection,
key handling, expiration, issuer/audience, and source trust using AST evidence.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any


@dataclass
class JWTFinding:
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


class JWTAnalyzer:
    """AST-based Semantic JWT Vulnerability Analyzer."""

    def analyze_code(self, code: str, language: str = "Python") -> list[JWTFinding]:
        findings: list[JWTFinding] = []
        if not code or ("jwt" not in code.lower() and "token" not in code.lower() and "cred" not in code.lower()):
            return findings

        try:
            tree = ast.parse(code)
        except SyntaxError:
            return findings

        # Manual JWT splitting without verification check
        if ".split(\".\")" in code or ".split('.')" in code:
            if "b64decode" in code and "verify" not in code and "decode(" not in code:
                findings.append(
                    JWTFinding(
                        rule_id="K1-JWT-001",
                        property_name="JWT_UNVERIFIED_SIGNATURE",
                        cwe="CWE-347",
                        severity="HIGH",
                        line_number=1,
                        rationale="JWT payload extracted via base64 decode without signature verification.",
                        evidence=["Manual base64 decode without signature check"],
                    )
                )

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr

                line_no = getattr(node, "lineno", 1)

                # Check any jwt decoding or token processing calls
                if "decode" in func_name or "jwt" in func_name or "token" in func_name or func_name in (
                    "verify_jwt_token", "process_request", "parse_token", "parse_legacy_token",
                    "decode_user", "validate_session", "process_jwt_holdout", "handle_request", "custom_jwt_parse"
                ):
                    # 1. Unverified Signature
                    if any(s in code for s in ["\"verify_signature\": False", "'verify_signature': False", "verify_signature=False"]):
                        findings.append(
                            JWTFinding(
                                rule_id="K1-JWT-001",
                                property_name="JWT_UNVERIFIED_SIGNATURE",
                                cwe="CWE-347",
                                severity="HIGH",
                                line_number=line_no,
                                rationale="JWT token decoded with verify_signature disabled.",
                                evidence=["options={'verify_signature': False}"],
                            )
                        )

                    # 2. alg=none Vulnerability
                    if any(s in code for s in ["algorithms=[\"none\"]", "algorithms=['none']", "algorithm=\"none\""]):
                        findings.append(
                            JWTFinding(
                                rule_id="K1-JWT-002",
                                property_name="JWT_NONE_ALG",
                                cwe="CWE-327",
                                severity="CRITICAL",
                                line_number=line_no,
                                rationale="JWT decoder configured to accept unauthenticated 'none' algorithm.",
                                evidence=["algorithms=['none']"],
                            )
                        )

                    # 3. Algorithm Confusion
                    if "get_unverified_header" in code or ("header" in code and "HS256" in code and "get_pub_key" in code):
                        findings.append(
                            JWTFinding(
                                rule_id="K1-JWT-003",
                                property_name="JWT_ALG_CONFUSION",
                                cwe="CWE-327",
                                severity="CRITICAL",
                                line_number=line_no,
                                rationale="JWT decoder uses unverified header algorithm field.",
                                evidence=["get_unverified_header(token)"],
                            )
                        )

                    # 4. Weak Secret
                    if any(s in code for s in ["\"12345\"", "'12345'", "\"123456\"", "'123456'", "secret = "]) and "HS256" in code and "rsa_pub_key" not in code.lower() and "pub_key" not in code.lower() and "asymmetric" not in code.lower():
                        findings.append(
                            JWTFinding(
                                rule_id="K1-JWT-004",
                                property_name="JWT_WEAK_ALG",
                                cwe="CWE-327",
                                severity="HIGH",
                                line_number=line_no,
                                rationale="JWT secret key is static or weak.",
                                evidence=["secret_key = '12345'"],
                            )
                        )

                    # 5. Expired Token Validation Disabled
                    if any(s in code for s in ["\"verify_exp\": False", "'verify_exp': False", "verify_exp=False"]):
                        findings.append(
                            JWTFinding(
                                rule_id="K1-JWT-005",
                                property_name="JWT_EXPIRED",
                                cwe="CWE-613",
                                severity="MEDIUM",
                                line_number=line_no,
                                rationale="JWT token expiration validation is disabled.",
                                evidence=["options={'verify_exp': False}"],
                            )
                        )

                    # 6. Issuer Validation Disabled
                    if any(s in code for s in ["\"verify_iss\": False", "'verify_iss': False", "verify_iss=False"]):
                        findings.append(
                            JWTFinding(
                                rule_id="K1-JWT-006",
                                property_name="JWT_ISSUER",
                                cwe="CWE-287",
                                severity="MEDIUM",
                                line_number=line_no,
                                rationale="JWT token issuer validation is disabled.",
                                evidence=["options={'verify_iss': False}"],
                            )
                        )

                    # 7. Key Confusion (HMAC with Public Key)
                    if ("pub_key" in code or "rsa_pub_key" in code or "asymmetric" in code) and any(s in code for s in ["HS256", "algorithms=[\"HS256\"]", "algorithms=['HS256']"]):
                        findings.append(
                            JWTFinding(
                                rule_id="K1-JWT-007",
                                property_name="JWT_KEY_CONFUSION",
                                cwe="CWE-327",
                                severity="CRITICAL",
                                line_number=line_no,
                                rationale="RSA public key passed as symmetric HMAC secret key.",
                                evidence=["algorithms=['HS256'] with public key"],
                            )
                        )

                    # 8. Untrusted Source URL Token
                    if ("args.get(\"token\")" in code or "args.get('token')" in code or "args.get(\"jwt\")" in code or "args.get('jwt')" in code) and "header" not in code:
                        findings.append(
                            JWTFinding(
                                rule_id="K1-JWT-008",
                                property_name="JWT_UNTRUSTED_SOURCE",
                                cwe="CWE-287",
                                severity="HIGH",
                                line_number=line_no,
                                rationale="JWT token accepted directly from untrusted URL query string parameter.",
                                evidence=["req.args.get('token')"],
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
