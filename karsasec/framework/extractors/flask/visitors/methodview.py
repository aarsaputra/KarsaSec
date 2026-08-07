"""AST Visitor for Flask MethodView classes."""

from __future__ import annotations

import ast

from karsasec.framework.extractors.flask.state import FlaskSemanticState, MethodViewRecord
from karsasec.framework.parser.ast_adapter import ASTNodeWrapper


class FlaskMethodViewVisitor:
    """Visits ClassDef AST nodes to detect MethodView class definitions and HTTP method handlers."""

    def __init__(self, state: FlaskSemanticState) -> None:
        self.state = state

    def visit(self, node: ASTNodeWrapper) -> None:
        """Inspects ClassDef AST nodes inheriting from MethodView or View."""
        if node.node_type != "ClassDef":
            return

        raw: ast.ClassDef = node.raw_node
        class_name = raw.name
        is_method_view = False

        for base in raw.bases:
            if isinstance(base, ast.Name) and base.id in ("MethodView", "View"):
                is_method_view = True
            elif isinstance(base, ast.Attribute) and base.attr in ("MethodView", "View"):
                is_method_view = True

        if not is_method_view:
            return

        methods_map: dict[str, str] = {}
        for item in raw.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fn_name = item.name.lower()
                if fn_name in ("get", "post", "put", "delete", "patch", "head", "options"):
                    methods_map[fn_name.upper()] = item.name

        mv_rec = MethodViewRecord(
            class_name=class_name,
            methods_map=methods_map,
            file_path=node.file_path,
            line=node.line,
        )
        self.state.method_views[class_name] = mv_rec
