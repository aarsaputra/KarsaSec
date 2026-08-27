"""Normalized Authentication & Authorization Guard Semantic Extractor for Sprint E10."""

from __future__ import annotations

from typing import Any

from karsasec.framework.extractors.base import ExtractionResult, ExtractorCapability, ExtractorContext, SemanticExtractor
from karsasec.framework.semantic_fact import ConfidenceLevel, SemanticFact, SemanticRole


class AuthSemanticExtractor(SemanticExtractor):
    """Additive semantic extractor discovering authentication and authorization guards."""

    @property
    def name(self) -> str:
        return "AuthSemanticExtractor"

    @property
    def priority(self) -> int:
        return 40

    @property
    def capabilities(self) -> tuple[ExtractorCapability, ...]:
        return (ExtractorCapability.AUTH,)

    @property
    def supported_frameworks(self) -> tuple[str, ...]:
        return ("GENERIC", "FLASK", "FASTAPI", "EXPRESS", "DJANGO")

    AUTH_PATTERNS = {
        "@login_required": (SemanticRole.AUTHENTICATION_CHECK, "login_required_decorator"),
        "passport.authenticate": (SemanticRole.AUTHENTICATION_CHECK, "passport_jwt_auth"),
        "@roles_required": (SemanticRole.AUTHORIZATION_CHECK, "role_based_auth"),
        "@permission_required": (SemanticRole.AUTHORIZATION_CHECK, "permission_check"),
        "check_permission(": (SemanticRole.AUTHORIZATION_CHECK, "permission_func_check"),
    }

    def collect(self, ctx: ExtractorContext) -> list[dict[str, Any]]:
        """Collects auth guard candidates from AST/CPG context."""
        if ctx.framework.upper() == "UNKNOWN":
            return []

        candidates = []
        for node in ctx.ast_nodes:
            code = ""
            if getattr(node, "attributes", None):
                code = str(node.attributes.get("code", "") or node.attributes.get("name", "") or "")
            if not code:
                code = str(getattr(node, "name", "") or getattr(node, "label", "") or "")

            node_id = getattr(node, "id", None) or getattr(node, "node_id", "memory_node")
            file_path = getattr(node, "file_path", None) or ctx.project_path or "unknown.py"
            line = int(getattr(node, "line_number", 0) or getattr(node, "line", 1) or 1)

            for pat, (role, guard_kind) in self.AUTH_PATTERNS.items():
                if pat in code:
                    candidates.append({
                        "node_id": str(node_id),
                        "symbol": code.split("(")[0].replace("@", "").strip() or pat,
                        "file": str(file_path),
                        "line": line,
                        "semantic_role": role,
                        "guard_kind": guard_kind,
                    })
                    break

        return candidates

    def emit(self, validated_items: list[dict[str, Any]], ctx: ExtractorContext) -> ExtractionResult:
        res = ExtractionResult()
        for item in validated_items:
            fact = SemanticFact.create(
                kind="auth",
                framework=ctx.framework,
                symbol=item["symbol"],
                file=item["file"],
                line=item["line"],
                node_id=item["node_id"],
                semantic_role=item["semantic_role"],
                metadata={"guard_kind": item["guard_kind"]},
                confidence=1.0,
                confidence_level=ConfidenceLevel.HIGH,
            )
            res.statistics[fact.fact_id] = fact.to_dict()
        return res
