"""Flask Middleware Collector orchestrating modular AST visitors across project files."""

from __future__ import annotations

from collections.abc import Sequence

from karsasec.framework.extractors.flask.middleware.state import FlaskMiddlewareState
from karsasec.framework.extractors.flask.middleware.visitors import (
    FlaskAfterRequestVisitor,
    FlaskBeforeRequestVisitor,
    FlaskClassMiddlewareVisitor,
    FlaskErrorHandlerVisitor,
    FlaskExtensionVisitor,
    FlaskTeardownVisitor,
)
from karsasec.framework.parser.ast_adapter import ASTNodeWrapper, PythonASTAdapter


class FlaskMiddlewareCollector:
    """Orchestrates 2-pass AST visitation over ASTNodeWrapper trees to populate FlaskMiddlewareState."""

    def __init__(self, state: FlaskMiddlewareState | None = None) -> None:
        self.state = state or FlaskMiddlewareState()
        self.extension_visitor = FlaskExtensionVisitor(self.state)
        self.before_visitor = FlaskBeforeRequestVisitor(self.state)
        self.after_visitor = FlaskAfterRequestVisitor(self.state)
        self.error_visitor = FlaskErrorHandlerVisitor(self.state)
        self.teardown_visitor = FlaskTeardownVisitor(self.state)
        self.class_visitor = FlaskClassMiddlewareVisitor(self.state)

    def collect_from_ast(self, root: ASTNodeWrapper | None) -> FlaskMiddlewareState:
        """Runs 2-pass visitation over a single AST tree."""
        if root is None:
            return self.state
        return self.collect_from_asts([root])

    def collect_from_asts(self, roots: Sequence[ASTNodeWrapper]) -> FlaskMiddlewareState:
        """Runs 2-pass collection across multiple AST trees for multi-file projects."""
        valid_roots = [r for r in roots if r is not None]

        # Pass 1: Extension discovery & app setup across all files
        for root in valid_roots:
            PythonASTAdapter.walk(root, lambda n: self.extension_visitor.visit(n))

        # Pass 2: Hook, error handler & class-based middleware collection across all files
        for root in valid_roots:

            def pass2(node: ASTNodeWrapper) -> None:
                self.before_visitor.visit(node)
                self.after_visitor.visit(node)
                self.error_visitor.visit(node)
                self.teardown_visitor.visit(node)
                self.class_visitor.visit(node)

            PythonASTAdapter.walk(root, pass2)

        return self.state
