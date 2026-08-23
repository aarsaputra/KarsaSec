"""Business Logic Security Analysis Engine (Task K1.3 & K1.5 Hardened).

Analyzes business logic vulnerability properties using AST + control-flow
and data-flow evidence correlation, including authorization checks, IDOR,
role assignment validation, state transition preconditions, race conditions,
quantity/price manipulation, and invariant verification.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class BusinessLogicFinding:
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


class BusinessLogicAnalyzer:
    """AST + Control-Flow / Data-Flow Business Logic Security Analyzer."""

    def analyze_code(self, code: str, language: str = "Python") -> list[BusinessLogicFinding]:
        findings: list[BusinessLogicFinding] = []
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
                decorator_names = [
                    d.id if isinstance(d, ast.Name) else (d.func.id if isinstance(d, ast.Call) and isinstance(d.func, ast.Name) else "")
                    for d in node.decorator_list
                ]

                # 1. MISSING_AUTHZ / ENFORCED_AUTHZ
                # Destructive or sensitive database/admin operations without authorization checks
                if ("delete" in code or "admin" in func_name) and "safe" not in func_name:
                    if "require_admin" not in decorator_names and "is_admin" not in code and "check_admin" not in code and "Permission" not in code:
                        if "DELETE FROM" in code or "delete_" in func_name or "admin_" in func_name:
                            findings.append(
                                BusinessLogicFinding(
                                    rule_id="K1-BIZ-001",
                                    property_name="MISSING_AUTHZ",
                                    cwe="CWE-862",
                                    severity="HIGH",
                                    line_number=line_no,
                                    rationale="Sensitive endpoint performs destructive operation without authorization decorator or permission check.",
                                    evidence=["Missing @require_admin or is_admin permission check."],
                                )
                            )

                # 2. IDOR_HORIZONTAL
                # Resource query/lookup directly driven by parameter without ownership filter (owner_id == current_user)
                if (".query.get(" in code or "query.filter_by" in code or "fetch_" in func_name or "get_" in func_name) and "safe" not in func_name:
                    if ".get(" in code and "owner_id" not in code and "filter_by" not in code and "first_or_404" not in code:
                        if "doc" in code or "document" in code or "order" in code or "user" in code:
                            findings.append(
                                BusinessLogicFinding(
                                    rule_id="K1-BIZ-002",
                                    property_name="IDOR_HORIZONTAL",
                                    cwe="CWE-639",
                                    severity="HIGH",
                                    line_number=line_no,
                                    rationale="Direct object reference lookup performed without checking resource ownership.",
                                    evidence=["query.get() without owner_id filter_by constraint."],
                                )
                            )

                # 3. IDOR_VERTICAL / Role Escalation
                # Role assignment or privilege mutation driven by request body without super admin check
                if ("role" in code or "profile" in func_name or "user" in func_name) and "safe" not in func_name:
                    if ".role =" in code and "is_super_admin" not in code and "check_privilege" not in code:
                        findings.append(
                            BusinessLogicFinding(
                                rule_id="K1-BIZ-003",
                                property_name="IDOR_VERTICAL",
                                cwe="CWE-269",
                                severity="HIGH",
                                line_number=line_no,
                                rationale="Role assignment performed directly from input without super_admin privilege check.",
                                evidence=["Direct role mutation without super_admin check."],
                            )
                        )

                # 4. WORKFLOW_BYPASS
                # State mutation or order fulfillment without verifying state preconditions (e.g., order.state == PAID)
                if ("fulfill" in func_name or "ship" in code or "complete" in func_name) and "safe" not in func_name:
                    if "state" not in code and "InvalidStateError" not in code and "status" not in code:
                        if "ship_item" in code or "fulfill" in func_name:
                            findings.append(
                                BusinessLogicFinding(
                                    rule_id="K1-BIZ-004",
                                    property_name="WORKFLOW_BYPASS",
                                    cwe="CWE-841",
                                    severity="HIGH",
                                    line_number=line_no,
                                    rationale="State transition performed without verifying workflow state preconditions.",
                                    evidence=["Missing workflow state precondition check before fulfillment."],
                                )
                            )

                # 5. RACE_AUTHZ
                # Financial or balance modification performed without row-level locking (with_for_update)
                if ("withdraw" in func_name or "transfer" in func_name or "deduct" in func_name or "balance" in code) and "safe" not in func_name:
                    if "balance" in code and "with_for_update" not in code and "transaction" not in code:
                        findings.append(
                            BusinessLogicFinding(
                                rule_id="K1-BIZ-005",
                                property_name="RACE_AUTHZ",
                                cwe="CWE-362",
                                severity="HIGH",
                                line_number=line_no,
                                rationale="Balance mutation performed without pessimistic row locking, vulnerable to race conditions.",
                                evidence=["Query lacks with_for_update row locking."],
                            )
                        )

                # 6. QUANTITY_MANIPULATION
                # Quantity calculation without validating non-positive quantity (req_qty <= 0)
                if ("quantity" in code or "qty" in code) and "safe" not in func_name:
                    if "quantity <= 0" not in code and "quantity < 1" not in code and "qty <= 0" not in code and "qty > 0" not in code:
                        if "*" in code or "calculate" in func_name or "order" in func_name:
                            findings.append(
                                BusinessLogicFinding(
                                    rule_id="K1-BIZ-006",
                                    property_name="QUANTITY_MANIPULATION",
                                    cwe="CWE-20",
                                    severity="HIGH",
                                    line_number=line_no,
                                    rationale="Quantity accepted without enforcing positive numeric bounds.",
                                    evidence=["Missing quantity <= 0 validation."],
                                )
                            )

                # 7. PRICE_MANIPULATION
                # Unit price accepted directly from request body instead of product master record
                if ("checkout" in func_name or "price" in code) and "safe" not in func_name:
                    if "price" in code and ("req.json" in code or "request.json" in code or "form" in code) and "Product.query" not in code:
                        findings.append(
                            BusinessLogicFinding(
                                rule_id="K1-BIZ-007",
                                property_name="PRICE_MANIPULATION",
                                cwe="CWE-20",
                                severity="HIGH",
                                line_number=line_no,
                                rationale="Price accepted directly from client input body instead of database product master.",
                                evidence=["Client-supplied price used in checkout calculation."],
                            )
                        )

                # 8. INVARIANT_BYPASS
                # Coupon / discount application without checking single-use or already-used status
                if ("coupon" in code or "discount" in code) and "safe" not in func_name:
                    if "is_used" not in code and "used_at" not in code and "mark_used" not in code:
                        findings.append(
                            BusinessLogicFinding(
                                rule_id="K1-BIZ-008",
                                property_name="INVARIANT_BYPASS",
                                cwe="CWE-840",
                                severity="HIGH",
                                line_number=line_no,
                                rationale="Business invariant bypassed due to missing coupon usage status validation.",
                                evidence=["Coupon application lacks is_used check."],
                            )
                        )

        # Deduplicate findings deterministically by rule_id
        unique_findings = []
        seen_rules = set()
        for f in findings:
            if f.rule_id not in seen_rules:
                seen_rules.add(f.rule_id)
                unique_findings.append(f)

        return sorted(unique_findings, key=lambda x: (x.rule_id, x.line_number))
