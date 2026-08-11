"""Flask Controller Collector orchestrating modular AST visitors across project files."""

from __future__ import annotations

from collections.abc import Sequence

from karsasec.framework.extractors.flask.controllers.state import FlaskControllerState
from karsasec.framework.extractors.flask.controllers.visitors import (
    FlaskBlueprintControllerVisitor,
    FlaskClassBasedViewVisitor,
    FlaskFunctionControllerVisitor,
    FlaskMethodViewVisitor,
)
from karsasec.framework.parser.ast_adapter import ASTNodeWrapper, PythonASTAdapter


class FlaskControllerCollector:
    """Orchestrates 2-pass AST visitation over ASTNodeWrapper trees to populate FlaskControllerState."""

    def __init__(self, state: FlaskControllerState | None = None) -> None:
        self.state = state or FlaskControllerState()
        self.blueprint_visitor = FlaskBlueprintControllerVisitor(self.state)
        self.method_view_visitor = FlaskMethodViewVisitor(self.state)
        self.class_view_visitor = FlaskClassBasedViewVisitor(self.state)
        self.function_visitor = FlaskFunctionControllerVisitor(self.state)

    def collect_from_ast(self, root: ASTNodeWrapper | None) -> FlaskControllerState:
        """Runs 2-pass visitation over a single AST tree."""
        if root is None:
            return self.state
        return self.collect_from_asts([root])

    def collect_from_asts(self, roots: Sequence[ASTNodeWrapper]) -> FlaskControllerState:
        """Runs 2-pass collection across multiple AST trees for multi-file projects."""
        valid_roots = [r for r in roots if r is not None]

        # Pass 1: Discover Blueprints, MethodViews, and as_view() bindings
        for root in valid_roots:
            def pass1(node: ASTNodeWrapper) -> None:
                self.blueprint_visitor.visit(node)
                self.method_view_visitor.visit(node)
                self.class_view_visitor.visit(node)

            PythonASTAdapter.walk(root, pass1)

        # Pass 2: Discover function controllers and resolve bindings
        for root in valid_roots:
            def pass2(node: ASTNodeWrapper) -> None:
                self.function_visitor.visit(node)

            PythonASTAdapter.walk(root, pass2)

        return self.state
