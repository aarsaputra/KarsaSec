"""Normalized HTTP Input Source Semantic Extractor for Sprint E10."""

from __future__ import annotations

from typing import Any

from karsasec.framework.extractors.base import ExtractionResult, ExtractorCapability, ExtractorContext, SemanticExtractor
from karsasec.framework.semantic_fact import ConfidenceLevel, SemanticFact, SemanticRole


class HTTPInputSourceExtractor(SemanticExtractor):
    """Additive semantic extractor discovering HTTP user-controlled input sources."""

    @property
    def name(self) -> str:
        return "HTTPInputSourceExtractor"

    @property
    def priority(self) -> int:
        return 20

    @property
    def capabilities(self) -> tuple[ExtractorCapability, ...]:
        return (ExtractorCapability.API,)

    @property
    def supported_frameworks(self) -> tuple[str, ...]:
        return ("GENERIC", "FLASK", "FASTAPI", "EXPRESS", "DJANGO", "PHP")

    INPUT_PATTERNS = {
        "request.args": "query_param",
        "request.form": "form_field",
        "request.json": "json_body",
        "req.query": "query_param",
        "req.body": "request_body",
        "$_GET": "query_param",
        "$_POST": "form_field",
        "request.GET": "query_param",
        "request.POST": "form_field",
    }

    def collect(self, ctx: ExtractorContext) -> list[dict[str, Any]]:
        """Collects input source candidates from AST/CPG context."""
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

            for pat, channel in self.INPUT_PATTERNS.items():
                if pat in code:
                    candidates.append({
                        "node_id": str(node_id),
                        "symbol": pat,
                        "file": str(file_path),
                        "line": line,
                        "channel": channel,
                        "framework_api": pat,
                    })
                    break

        return candidates

    def emit(self, validated_items: list[dict[str, Any]], ctx: ExtractorContext) -> ExtractionResult:
        res = ExtractionResult()
        for item in validated_items:
            fact = SemanticFact.create(
                kind="source",
                framework=ctx.framework,
                symbol=item["symbol"],
                file=item["file"],
                line=item["line"],
                node_id=item["node_id"],
                semantic_role=SemanticRole.HTTP_INPUT,
                source_kind="http_user_input",
                metadata={"channel": item["channel"], "framework_api": item["framework_api"]},
                confidence=1.0,
                confidence_level=ConfidenceLevel.HIGH,
            )
            res.statistics[fact.fact_id] = fact.to_dict()
        return res
