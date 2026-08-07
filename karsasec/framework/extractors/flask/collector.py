"""Flask Route Collector orchestrating modular AST visitors across project files."""

from __future__ import annotations

from collections.abc import Sequence

from karsasec.framework.extractors.flask.state import FlaskSemanticState
from karsasec.framework.extractors.flask.visitors import (
    FlaskBlueprintVisitor,
    FlaskCallVisitor,
    FlaskDecoratorResolver,
    FlaskMethodViewVisitor,
    FlaskRouteVisitor,
)
from karsasec.framework.parser.ast_adapter import ASTNodeWrapper, PythonASTAdapter


class FlaskRouteCollector:
    """Orchestrates modular AST visitors over ASTNodeWrapper trees to populate FlaskSemanticState."""

    def __init__(self, state: FlaskSemanticState | None = None) -> None:
        self.state = state or FlaskSemanticState()
        self.decorator_resolver = FlaskDecoratorResolver(self.state)
        self.blueprint_visitor = FlaskBlueprintVisitor(self.state)
        self.methodview_visitor = FlaskMethodViewVisitor(self.state)
        self.call_visitor = FlaskCallVisitor(self.state)
        self.route_visitor = FlaskRouteVisitor(self.state)

    def collect_from_ast(self, root: ASTNodeWrapper) -> FlaskSemanticState:
        """Runs a 2-pass visitation over a single AST tree."""
        # Pass 1: Decorators, Blueprints, MethodViews, Calls
        def pass1(node: ASTNodeWrapper) -> None:
            self.decorator_resolver.visit(node)
            self.blueprint_visitor.visit(node)
            self.methodview_visitor.visit(node)
            self.call_visitor.visit(node)

        PythonASTAdapter.walk(root, pass1)

        # Pass 2: Function Route Decorators
        def pass2(node: ASTNodeWrapper) -> None:
            self.route_visitor.visit(node)

        PythonASTAdapter.walk(root, pass2)

        return self.state

    def collect_from_asts(self, roots: Sequence[ASTNodeWrapper]) -> FlaskSemanticState:
        """Runs 2-pass collection across multiple AST trees."""
        for root in roots:
            self.collect_from_ast(root)
        return self.state
