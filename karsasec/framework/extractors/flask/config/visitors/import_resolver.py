"""AST Visitor for discovering imported configuration modules and class symbols."""

from __future__ import annotations

import ast

from karsasec.framework.extractors.flask.config.state import FlaskConfigState
from karsasec.framework.parser.ast_adapter import ASTNodeWrapper


class FlaskImportResolverVisitor:
    """Visits Import and ImportFrom AST nodes to record configuration imports."""

    def __init__(self, state: FlaskConfigState) -> None:
        self.state = state

    def visit(self, node: ASTNodeWrapper) -> None:
        raw = node.raw_node

        if isinstance(raw, ast.Import):
            for alias in raw.names:
                name = alias.asname or alias.name
                self.state.register_import(name, alias.name)

        elif isinstance(raw, ast.ImportFrom):
            mod_name = raw.module or ""
            for alias in raw.names:
                name = alias.asname or alias.name
                self.state.register_import(name, f"{mod_name}.{alias.name}")
