"""AST Visitor for resolving decorator aliases, assignments, and nested wrapper chains."""

from __future__ import annotations

import ast

from karsasec.framework.extractors.flask.state import FlaskSemanticState
from karsasec.framework.parser.ast_adapter import ASTNodeWrapper


class FlaskDecoratorResolver:
    """Visits Assign AST nodes to track decorator aliases (e.g. route = app.route; r = route)."""

    def __init__(self, state: FlaskSemanticState) -> None:
        self.state = state

    def visit(self, node: ASTNodeWrapper) -> None:
        """Inspects Assign AST nodes for alias assignments."""
        if node.node_type != "Assign":
            return

        raw: ast.Assign = node.raw_node
        if not raw.targets or not isinstance(raw.targets[0], ast.Name):
            return

        alias_name = raw.targets[0].id
        target_expr = raw.value

        target_str = ""
        if isinstance(target_expr, ast.Attribute):
            if isinstance(target_expr.value, ast.Name):
                target_str = f"{target_expr.value.id}.{target_expr.attr}"
        elif isinstance(target_expr, ast.Name):
            target_str = target_expr.id

        if target_str and ("route" in target_str or "get" in target_str or "post" in target_str or target_str in self.state.aliases):
            self.state.add_alias(alias_name, target_str)
