"""Flask Configuration Collector orchestrating 2-pass AST visitation across project files."""

from __future__ import annotations

from collections.abc import Sequence

from karsasec.framework.extractors.flask.config.state import FlaskConfigState
from karsasec.framework.extractors.flask.config.visitors import (
    FlaskConfigClassVisitor,
    FlaskConfigLoaderVisitor,
    FlaskConfigUpdateVisitor,
    FlaskDirectConfigVisitor,
    FlaskEnvironmentVisitor,
    FlaskFactoryVisitor,
    FlaskImportResolverVisitor,
)
from karsasec.framework.parser.ast_adapter import ASTNodeWrapper, PythonASTAdapter


class FlaskConfigCollector:
    """Orchestrates 2-pass AST visitation over ASTNodeWrapper trees to populate FlaskConfigState."""

    def __init__(self, state: FlaskConfigState | None = None) -> None:
        self.state = state or FlaskConfigState()
        self.import_visitor = FlaskImportResolverVisitor(self.state)
        self.config_class_visitor = FlaskConfigClassVisitor(self.state)
        self.env_visitor = FlaskEnvironmentVisitor(self.state)
        self.direct_assign_visitor = FlaskDirectConfigVisitor(self.state)
        self.update_visitor = FlaskConfigUpdateVisitor(self.state)
        self.loader_visitor = FlaskConfigLoaderVisitor(self.state)
        self.factory_visitor = FlaskFactoryVisitor(self.state)

    def collect_from_ast(self, root: ASTNodeWrapper | None) -> FlaskConfigState:
        """Runs 2-pass visitation over a single AST tree."""
        if root is None:
            return self.state
        return self.collect_from_asts([root])

    def collect_from_asts(self, roots: Sequence[ASTNodeWrapper]) -> FlaskConfigState:
        """Runs 2-pass collection across multiple AST trees for multi-file projects."""
        valid_roots = [r for r in roots if r is not None]

        # Pass 1: Discover imports, config classes, and environment variables
        for root in valid_roots:

            def pass1(node: ASTNodeWrapper) -> None:
                self.import_visitor.visit(node)
                self.config_class_visitor.visit(node)
                self.env_visitor.visit(node)

            PythonASTAdapter.walk(root, pass1)

        # Pass 2: Discover direct assignments, updates, loaders, and factory patterns
        for root in valid_roots:

            def pass2(node: ASTNodeWrapper) -> None:
                self.direct_assign_visitor.visit(node)
                self.update_visitor.visit(node)
                self.loader_visitor.visit(node)
                self.factory_visitor.visit(node)

            PythonASTAdapter.walk(root, pass2)

        return self.state
