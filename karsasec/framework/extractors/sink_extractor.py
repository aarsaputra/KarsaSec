"""Normalized Security Sink Semantic Extractor for Sprint E10."""

from __future__ import annotations

from typing import Any

from karsasec.framework.extractors.base import ExtractionResult, ExtractorCapability, ExtractorContext, SemanticExtractor
from karsasec.framework.semantic_fact import ConfidenceLevel, SemanticFact, SemanticRole


class SecuritySinkExtractor(SemanticExtractor):
    """Additive semantic extractor discovering security-sensitive sinks."""

    @property
    def name(self) -> str:
        return "SecuritySinkExtractor"

    @property
    def priority(self) -> int:
        return 30

    @property
    def capabilities(self) -> tuple[ExtractorCapability, ...]:
        return (ExtractorCapability.ORM, ExtractorCapability.API)

    @property
    def supported_frameworks(self) -> tuple[str, ...]:
        return ("GENERIC", "FLASK", "FASTAPI", "EXPRESS", "DJANGO", "PHP")

    SINK_PATTERNS = {
        "execute(": ("sql", "database_execute"),
        "raw(": ("sql", "orm_raw_query"),
        "os.system": ("command_execution", "shell_execution"),
        "subprocess.run": ("command_execution", "process_execution"),
        "exec(": ("code_execution", "dynamic_eval"),
        "eval(": ("code_execution", "dynamic_eval"),
        "include(": ("path_resolution", "file_include"),
        "render_template(": ("template_render", "template_engine"),
    }

    def collect(self, ctx: ExtractorContext) -> list[dict[str, Any]]:
        """Collects security sink candidates from AST/CPG context."""
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

            for pat, (category, role_detail) in self.SINK_PATTERNS.items():
                if pat in code:
                    candidates.append({
                        "node_id": str(node_id),
                        "symbol": code.split("(")[0].strip() or pat,
                        "file": str(file_path),
                        "line": line,
                        "sink_category": category,
                        "role_detail": role_detail,
                    })
                    break

        return candidates

    def emit(self, validated_items: list[dict[str, Any]], ctx: ExtractorContext) -> ExtractionResult:
        res = ExtractionResult()
        for item in validated_items:
            fact = SemanticFact.create(
                kind="sink",
                framework=ctx.framework,
                symbol=item["symbol"],
                file=item["file"],
                line=item["line"],
                node_id=item["node_id"],
                semantic_role=SemanticRole.SECURITY_SINK,
                sink_category=item["sink_category"],
                metadata={"role_detail": item["role_detail"]},
                confidence=1.0,
                confidence_level=ConfidenceLevel.HIGH,
            )
            res.statistics[fact.fact_id] = fact.to_dict()
        return res
