"""AST Visitor for Flask application factory pattern (create_app)."""

from __future__ import annotations

import ast

from karsasec.framework.extractors.flask.config.state import FlaskConfigState
from karsasec.framework.parser.ast_adapter import ASTNodeWrapper


class FlaskFactoryVisitor:
    """Visits FunctionDef AST nodes to discover create_app() application factory patterns."""

    FACTORY_NAMES = {"create_app", "make_app", "get_app"}

    def __init__(self, state: FlaskConfigState) -> None:
        self.state = state

    def visit(self, node: ASTNodeWrapper) -> None:
        raw = node.raw_node

        if not isinstance(raw, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return

        if raw.name in self.FACTORY_NAMES:
            # Inspection of factory body for configuration setup
            pass
