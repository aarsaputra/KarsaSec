"""Normalized Security Configuration Semantic Extractor for Sprint E10."""

from __future__ import annotations

from typing import Any

from karsasec.framework.extractors.base import ExtractionResult, ExtractorCapability, ExtractorContext, SemanticExtractor
from karsasec.framework.semantic_fact import ConfidenceLevel, SemanticFact, SemanticRole


class ConfigurationSemanticExtractor(SemanticExtractor):
    """Additive semantic extractor discovering security configuration settings."""

    @property
    def name(self) -> str:
        return "ConfigurationSemanticExtractor"

    @property
    def priority(self) -> int:
        return 60

    @property
    def capabilities(self) -> tuple[ExtractorCapability, ...]:
        return (ExtractorCapability.CONFIG,)

    @property
    def supported_frameworks(self) -> tuple[str, ...]:
        return ("GENERIC", "FLASK", "FASTAPI", "EXPRESS", "DJANGO")

    CONFIG_PATTERNS = {
        "DEBUG": "debug_mode",
        "CORS": "cors_configuration",
        "ALLOWED_HOSTS": "trusted_hosts",
        "CSRF": "csrf_protection",
        "SECRET_KEY": "secret_key_configuration",
    }

    def collect(self, ctx: ExtractorContext) -> list[dict[str, Any]]:
        """Collects security configuration candidate nodes from AST/CPG context."""
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

            for key, config_type in self.CONFIG_PATTERNS.items():
                if key in code:
                    candidates.append({
                        "node_id": str(node_id),
                        "symbol": key,
                        "file": str(file_path),
                        "line": line,
                        "config_type": config_type,
                    })
                    break

        return candidates

    def emit(self, validated_items: list[dict[str, Any]], ctx: ExtractorContext) -> ExtractionResult:
        res = ExtractionResult()
        for item in validated_items:
            fact = SemanticFact.create(
                kind="config",
                framework=ctx.framework,
                symbol=item["symbol"],
                file=item["file"],
                line=item["line"],
                node_id=item["node_id"],
                semantic_role=SemanticRole.SECURITY_CONFIGURATION,
                metadata={"config_type": item["config_type"]},
                confidence=1.0,
                confidence_level=ConfidenceLevel.HIGH,
            )
            res.statistics[fact.fact_id] = fact.to_dict()
        return res
