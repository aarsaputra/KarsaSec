"""Normalized Middleware Registration Semantic Extractor for Sprint E10."""

from __future__ import annotations

from typing import Any

from karsasec.framework.extractors.base import ExtractionResult, ExtractorCapability, ExtractorContext, SemanticExtractor
from karsasec.framework.semantic_fact import ConfidenceLevel, SemanticFact, SemanticRole


class MiddlewareSemanticExtractor(SemanticExtractor):
    """Additive semantic extractor discovering middleware registrations."""

    @property
    def name(self) -> str:
        return "MiddlewareSemanticExtractor"

    @property
    def priority(self) -> int:
        return 50

    @property
    def capabilities(self) -> tuple[ExtractorCapability, ...]:
        return (ExtractorCapability.MIDDLEWARE,)

    @property
    def supported_frameworks(self) -> tuple[str, ...]:
        return ("GENERIC", "FLASK", "FASTAPI", "EXPRESS", "DJANGO")

    MIDDLEWARE_PATTERNS = ("app.use(", "app.add_middleware(", "MIDDLEWARE =", "MIDDLEWARE_CLASSES =")

    def collect(self, ctx: ExtractorContext) -> list[dict[str, Any]]:
        """Collects middleware candidate nodes from AST/CPG context."""
        if ctx.framework.upper() == "UNKNOWN":
            return []

        candidates = []
        for idx, node in enumerate(ctx.ast_nodes):
            code = ""
            if getattr(node, "attributes", None):
                code = str(node.attributes.get("code", "") or node.attributes.get("name", "") or "")
            if not code:
                code = str(getattr(node, "name", "") or getattr(node, "label", "") or "")

            node_id = getattr(node, "id", None) or getattr(node, "node_id", "memory_node")
            file_path = getattr(node, "file_path", None) or ctx.project_path or "unknown.py"
            line = int(getattr(node, "line_number", 0) or getattr(node, "line", 1) or 1)

            for pat in self.MIDDLEWARE_PATTERNS:
                if pat in code:
                    candidates.append({
                        "node_id": str(node_id),
                        "symbol": code.split("(")[0].strip() or pat,
                        "file": str(file_path),
                        "line": line,
                        "execution_order": idx + 1,
                    })
                    break

        return candidates

    def emit(self, validated_items: list[dict[str, Any]], ctx: ExtractorContext) -> ExtractionResult:
        res = ExtractionResult()
        for item in validated_items:
            fact = SemanticFact.create(
                kind="middleware",
                framework=ctx.framework,
                symbol=item["symbol"],
                file=item["file"],
                line=item["line"],
                node_id=item["node_id"],
                semantic_role=SemanticRole.MIDDLEWARE,
                metadata={"execution_order": item["execution_order"]},
                confidence=1.0,
                confidence_level=ConfidenceLevel.HIGH,
            )
            res.statistics[fact.fact_id] = fact.to_dict()
        return res
