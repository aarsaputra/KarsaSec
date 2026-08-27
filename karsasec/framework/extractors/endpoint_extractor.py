"""Normalized HTTP Endpoint Semantic Extractor for Sprint E10."""

from __future__ import annotations

import re
from typing import Any

from karsasec.framework.extractors.base import ExtractionResult, ExtractorCapability, ExtractorContext, SemanticExtractor
from karsasec.framework.semantic_fact import ConfidenceLevel, SemanticFact, SemanticRole


class HTTPEndpointExtractor(SemanticExtractor):
    """Additive semantic extractor discovering HTTP routes and endpoints across frameworks."""

    @property
    def name(self) -> str:
        return "HTTPEndpointExtractor"

    @property
    def priority(self) -> int:
        return 10

    @property
    def capabilities(self) -> tuple[ExtractorCapability, ...]:
        return (ExtractorCapability.ROUTING,)

    @property
    def supported_frameworks(self) -> tuple[str, ...]:
        return ("GENERIC", "FLASK", "FASTAPI", "EXPRESS", "DJANGO")

    def collect(self, ctx: ExtractorContext) -> list[dict[str, Any]]:
        """Collects endpoint candidate nodes from AST/CPG context."""
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

            # Route decorator patterns: @app.route('/path', methods=['GET', 'POST'])
            if "@" in code and "route" in code:
                path_match = re.search(r"['\"](/[^'\"]*)['\"]", code)
                method_match = re.search(r"methods\s*=\s*\[([^\]]+)\]", code)
                path = path_match.group(1) if path_match else "/"
                methods = [m.strip("'\" ") for m in method_match.group(1).split(",")] if method_match else ["GET"]
                for method in methods:
                    candidates.append({
                        "node_id": str(node_id),
                        "symbol": code.split("(")[0].replace("@", "").strip(),
                        "file": str(file_path),
                        "line": line,
                        "method": method.upper(),
                        "path": path,
                    })

            # Decorators or call expressions: app.get('/path'), router.post('/path')
            elif any(pat in code for pat in ("app.get", "app.post", "router.get", "router.post", "http.HandleFunc")):
                method = "POST" if "post" in code.lower() else "GET"
                path_match = re.search(r"['\"](/[^'\"]*)['\"]", code)
                path = path_match.group(1) if path_match else "/"
                candidates.append({
                    "node_id": str(node_id),
                    "symbol": code.split("(")[0].strip(),
                    "file": str(file_path),
                    "line": line,
                    "method": method,
                    "path": path,
                })

        return candidates

    def emit(self, validated_items: list[dict[str, Any]], ctx: ExtractorContext) -> ExtractionResult:
        res = ExtractionResult()
        for item in validated_items:
            fact = SemanticFact.create(
                kind="endpoint",
                framework=ctx.framework,
                symbol=item["symbol"],
                file=item["file"],
                line=item["line"],
                node_id=item["node_id"],
                semantic_role=SemanticRole.HTTP_ENDPOINT,
                metadata={"method": item["method"], "path": item["path"]},
                confidence=1.0,
                confidence_level=ConfidenceLevel.HIGH,
            )
            # Attach fact ID to result statistics/telemetry deterministically
            res.statistics[fact.fact_id] = fact.to_dict()
        return res
