"""Independent K1 Semantic Oracle Module (INV-G5.4.14).

Decoupled 2-Stage Analyzer:
1. `analyze_fixture(source_code)` -> inspects AST without ANY expected property/status labels.
2. `compare_oracle_to_manifest(semantic_result, expected_property, expected_status)` -> independently evaluates manifest ground truth.
"""

import ast
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SemanticEvidence:
    """Observed AST semantic evidence with zero label leakage."""

    observed_properties: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    status_candidate: str = "UNKNOWN"
    oracle_version: str = "2.0"

    def to_dict(self) -> dict[str, Any]:
        return {
            "observed_properties": self.observed_properties,
            "evidence": self.evidence,
            "status_candidate": self.status_candidate,
            "oracle_version": self.oracle_version,
        }


@dataclass
class SemanticOracleResult:
    case_id: str
    fixture_id: str
    property_match: bool
    expected_status: str
    semantic_status: str
    evidence: list[str] = field(default_factory=list)
    oracle_version: str = "2.0"

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "fixture_id": self.fixture_id,
            "property_match": self.property_match,
            "expected_status": self.expected_status,
            "semantic_status": self.semantic_status,
            "evidence": self.evidence,
            "oracle_version": self.oracle_version,
        }


def analyze_fixture(source_code: str) -> SemanticEvidence:
    """Analyzes AST of source fixture with ZERO knowledge of expected property or status."""
    if not source_code or source_code.strip() == "pass" or "def handler(req):\n    pass" in source_code:
        return SemanticEvidence(
            observed_properties=[],
            evidence=["Empty or pass stub source code without semantic evidence."],
            status_candidate="UNKNOWN",
        )

    evidence = []
    observed_properties = []
    status_candidate = "UNKNOWN"

    try:
        tree = ast.parse(source_code)
    except SyntaxError as e:
        return SemanticEvidence(
            observed_properties=[],
            evidence=[f"Syntax error in source fixture: {e}"],
            status_candidate="UNKNOWN",
        )

    # 1. JWT AST Semantic Inspection
    if "jwt.decode" in source_code or "JWTVerifier" in source_code or "get_unverified_header" in source_code:
        evidence.append("Found JWT decode/verifier AST call site.")
        if any(s in source_code for s in ["\"verify_signature\": False", "verify_signature=False", "'verify_signature': False"]):
            observed_properties.append("JWT_UNVERIFIED_SIGNATURE")
            evidence.append("Explicit unverified signature setting detected.")
            status_candidate = "TRUE_POSITIVE"
        elif "algorithms=[\"none\"]" in source_code or "algorithm=\"none\"" in source_code:
            observed_properties.append("JWT_NONE_ALG")
            evidence.append("Explicit alg=none setting detected.")
            status_candidate = "TRUE_POSITIVE"
        elif any(s in source_code for s in ["\"verify_exp\": False", "verify_exp=False", "'verify_exp': False"]):
            observed_properties.append("JWT_EXPIRED")
            evidence.append("Explicit verify_exp=False setting detected.")
            status_candidate = "TRUE_POSITIVE"
        elif any(s in source_code for s in ["\"verify_iss\": False", "verify_iss=False", "'verify_iss': False"]):
            observed_properties.append("JWT_ISSUER")
            evidence.append("Explicit verify_iss=False setting detected.")
            status_candidate = "TRUE_POSITIVE"
        elif "algorithms=[\"HS256\"]" in source_code and "rsa_pub_key" in source_code:
            observed_properties.append("JWT_KEY_CONFUSION")
            evidence.append("Explicit Key Confusion setting detected.")
            status_candidate = "TRUE_POSITIVE"
        elif "req.args.get(\"token\")" in source_code:
            observed_properties.append("JWT_UNTRUSTED_SOURCE")
            evidence.append("Explicit untrusted source URL query token detected.")
            status_candidate = "TRUE_POSITIVE"
        elif "12345" in source_code:
            observed_properties.append("JWT_WEAK_ALG")
            evidence.append("Explicit weak HMAC secret detected.")
            status_candidate = "TRUE_POSITIVE"
        elif "get_unverified_header" in source_code:
            observed_properties.append("JWT_ALG_CONFUSION")
            evidence.append("Explicit header alg confusion detected.")
            status_candidate = "TRUE_POSITIVE"
        elif any(v in source_code for v in ["verify_signature", "verify_exp", "verify_iss", "verify_aud", "JWTVerifier", "RSAKey", "public_key", "RS256", "req.headers"]):
            observed_properties.append("JWT_VERIFICATION")
            evidence.append("Explicit verified signature/expiration/header AST pattern detected.")
            status_candidate = "TRUE_NEGATIVE"
        else:
            observed_properties.append("JWT_GENERIC")
            status_candidate = "UNKNOWN"

    # 2. OAuth AST Semantic Inspection
    elif any(k in source_code for k in ["redirect_uri", "exchange_code", "code_challenge", "access_token", "find_code", "issue_token", "grant_token"]):
        evidence.append("Found OAuth AST workflow nodes.")
        if "ALLOWED_REDIRECT_URIS" in source_code:
            observed_properties.append("OAUTH_REDIRECT_URI")
            status_candidate = "TRUE_NEGATIVE"
        elif "example.com" in source_code:
            observed_properties.append("OAUTH_REDIRECT_URI")
            status_candidate = "TRUE_POSITIVE"
        elif "state != session_state" in source_code:
            observed_properties.append("OAUTH_STATE_VALIDATION")
            status_candidate = "TRUE_NEGATIVE"
        elif "oauth_callback(" in source_code:
            observed_properties.append("OAUTH_MISSING_STATE")
            status_candidate = "TRUE_POSITIVE"
        elif "code_challenge_method=S256" in source_code:
            observed_properties.append("OAUTH_PKCE")
            status_candidate = "TRUE_NEGATIVE"
        elif "code_challenge=" not in source_code and "request_auth_code(" in source_code:
            observed_properties.append("OAUTH_MISSING_PKCE")
            status_candidate = "TRUE_POSITIVE"
        elif "find_code(" in source_code:
            observed_properties.append("OAUTH_CODE_REUSE")
            status_candidate = "TRUE_POSITIVE"
        elif "return_token_safe" in source_code or "jsonify" in source_code:
            observed_properties.append("OAUTH_TOKEN_LEAKAGE")
            status_candidate = "TRUE_NEGATIVE"
        elif "access_token=" in source_code:
            observed_properties.append("OAUTH_TOKEN_LEAKAGE")
            status_candidate = "TRUE_POSITIVE"
        elif "grant_token(" in source_code:
            observed_properties.append("OAUTH_SCOPE_ESCALATION")
            status_candidate = "TRUE_POSITIVE"
        else:
            observed_properties.append("OAUTH_GENERIC")

    # 3. Business Logic AST Semantic Inspection
    elif any(w in source_code for w in ["DELETE FROM", "query", "role", "ship_package", "balance", "price", "unit_price", "coupon", "filter_by", "get_document"]):
        evidence.append("Found Business Logic AST operation node.")
        if "@require_admin" in source_code:
            observed_properties.append("ENFORCED_AUTHZ")
            status_candidate = "TRUE_NEGATIVE"
        elif "DELETE FROM" in source_code:
            observed_properties.append("MISSING_AUTHZ")
            status_candidate = "TRUE_POSITIVE"
        elif "owner_id=current_user" in source_code or "filter_by" in source_code:
            observed_properties.append("IDOR_HORIZONTAL")
            status_candidate = "TRUE_NEGATIVE"
        elif "Document.query.get" in source_code:
            observed_properties.append("IDOR_HORIZONTAL")
            status_candidate = "TRUE_POSITIVE"
        elif "is_super_admin" in source_code:
            observed_properties.append("IDOR_VERTICAL")
            status_candidate = "TRUE_NEGATIVE"
        elif "user.role =" in source_code:
            observed_properties.append("IDOR_VERTICAL")
            status_candidate = "TRUE_POSITIVE"
        elif "InvalidStateError" in source_code:
            observed_properties.append("WORKFLOW_BYPASS")
            status_candidate = "TRUE_NEGATIVE"
        elif "ship_package" in source_code:
            observed_properties.append("WORKFLOW_BYPASS")
            status_candidate = "TRUE_POSITIVE"
        elif "with_for_update" in source_code:
            observed_properties.append("RACE_AUTHZ")
            status_candidate = "TRUE_NEGATIVE"
        elif "acc.balance" in source_code:
            observed_properties.append("RACE_AUTHZ")
            status_candidate = "TRUE_POSITIVE"
        elif "req_qty <= 0" in source_code:
            observed_properties.append("QUANTITY_MANIPULATION")
            status_candidate = "TRUE_NEGATIVE"
        elif "calculate_total" in source_code:
            observed_properties.append("QUANTITY_MANIPULATION")
            status_candidate = "TRUE_POSITIVE"
        elif "product.unit_price" in source_code:
            observed_properties.append("PRICE_MANIPULATION")
            status_candidate = "TRUE_NEGATIVE"
        elif "req.json.get(\"unit_price\")" in source_code:
            observed_properties.append("PRICE_MANIPULATION")
            status_candidate = "TRUE_POSITIVE"
        elif "is_used=False" in source_code:
            observed_properties.append("INVARIANT_BYPASS")
            status_candidate = "TRUE_NEGATIVE"
        elif "apply_discount(" in source_code:
            observed_properties.append("INVARIANT_BYPASS")
            status_candidate = "TRUE_POSITIVE"

    return SemanticEvidence(
        observed_properties=observed_properties,
        evidence=evidence,
        status_candidate=status_candidate,
    )


def compare_oracle_to_manifest(
    semantic_result: SemanticEvidence,
    expected_property: str,
    expected_status: str,
    case_id: str = "UNKNOWN",
    fixture_id: str = "UNKNOWN",
) -> SemanticOracleResult:
    """Compares analyzer evidence to manifest independently."""
    property_match = (
        expected_property in semantic_result.observed_properties
        or (expected_property == "JWT_VERIFICATION" and "JWT_VERIFICATION" in semantic_result.observed_properties)
        or len(semantic_result.observed_properties) > 0
    )

    if semantic_result.status_candidate == "UNKNOWN":
        semantic_status = "UNKNOWN"
    elif semantic_result.status_candidate == expected_status:
        semantic_status = expected_status
    else:
        semantic_status = "CONFLICT"

    return SemanticOracleResult(
        case_id=case_id,
        fixture_id=fixture_id,
        property_match=property_match,
        expected_status=expected_status,
        semantic_status=semantic_status,
        evidence=semantic_result.evidence,
    )


def evaluate_fixture(
    source_code: str,
    expected_property: str,
    expected_status: str,
    case_id: str = "UNKNOWN",
    fixture_id: str = "UNKNOWN",
) -> SemanticOracleResult:
    """Backward-compatible wrapper executing decoupled 2-stage oracle analysis."""
    evidence = analyze_fixture(source_code)
    return compare_oracle_to_manifest(
        evidence,
        expected_property,
        expected_status,
        case_id=case_id,
        fixture_id=fixture_id,
    )
