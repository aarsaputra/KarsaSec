"""Flask Route Semantic Extractor implementing 3-phase collect -> validate -> emit lifecycle."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from karsasec.framework.extractors.base import (
    ExtractionResult,
    ExtractorCapability,
    ExtractorContext,
    SemanticExtractor,
)
from karsasec.framework.extractors.flask.collector import FlaskRouteCollector
from karsasec.framework.extractors.flask.normalizer import FlaskRouteNormalizer
from karsasec.framework.extractors.flask.state import FlaskSemanticState
from karsasec.framework.intermediate import IntermediateSemanticRepresentation, RouteDefinition
from karsasec.framework.parser.ast_adapter import ASTNodeWrapper, PythonASTAdapter


class FlaskRouteExtractor(SemanticExtractor):
    """Semantic Extractor for Flask routes, blueprints, method views, and add_url_rules."""

    @property
    def name(self) -> str:
        return "FlaskRouteExtractor"

    @property
    def priority(self) -> int:
        return 10

    @property
    def supported_languages(self) -> tuple[str, ...]:
        return ("Python",)

    @property
    def supported_frameworks(self) -> tuple[str, ...]:
        return ("FLASK",)

    @property
    def capabilities(self) -> tuple[ExtractorCapability, ...]:
        return (ExtractorCapability.ROUTING,)

    def collect(self, ctx: ExtractorContext) -> FlaskSemanticState:
        """Phase 1: Parses AST trees and collects raw route candidates into FlaskSemanticState."""
        state = FlaskSemanticState()
        collector = FlaskRouteCollector(state=state)

        ast_trees: list[ASTNodeWrapper] = []

        # 1. AST nodes passed directly in context
        if ctx.ast_nodes:
            for node in ctx.ast_nodes:
                if isinstance(node, ASTNodeWrapper):
                    ast_trees.append(node)
                elif hasattr(node, "body") or hasattr(node, "__class__"):
                    ast_trees.append(PythonASTAdapter.from_ast(node))

        # 2. Project path files scan
        if ctx.project_path:
            p_path = Path(ctx.project_path)
            if p_path.is_file() and p_path.suffix == ".py":
                tree = PythonASTAdapter.parse_file(p_path)
                if tree:
                    ast_trees.append(tree)
            elif p_path.is_dir():
                for py_file in p_path.rglob("*.py"):
                    tree = PythonASTAdapter.parse_file(py_file)
                    if tree:
                        ast_trees.append(tree)

        collector.collect_from_asts(ast_trees)
        return state

    def validate(self, raw_state: FlaskSemanticState, ctx: ExtractorContext) -> tuple[list[RouteDefinition], list[Any]]:
        """Phase 2: Normalizes raw records and validates routes."""
        normalizer = FlaskRouteNormalizer(state=raw_state)
        routes = normalizer.normalize(raw_state.routes)

        diagnostics: list[Any] = []
        # Check for duplicated route paths & methods
        seen: set[tuple[str, str]] = set()
        for r in routes:
            key = (r.method.upper(), r.path)
            if key in seen:
                ctx.logger.warning("Duplicate route detected: %s %s", r.method, r.path)
            seen.add(key)

        return routes, diagnostics

    def emit(self, validated_routes: list[RouteDefinition], ctx: ExtractorContext) -> ExtractionResult:
        """Phase 3: Emits IntermediateSemanticRepresentation containing validated routes."""
        isr = IntermediateSemanticRepresentation(routes=tuple(validated_routes))
        return ExtractionResult(
            isr=isr,
            statistics={"routes_count": len(validated_routes)},
        )
