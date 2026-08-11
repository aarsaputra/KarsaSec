"""AST Visitor for Flask as_view() class-based view registrations."""

from __future__ import annotations

import ast

from karsasec.framework.extractors.flask.controllers.state import FlaskControllerState
from karsasec.framework.parser.ast_adapter import ASTNodeWrapper


class FlaskClassBasedViewVisitor:
    """Visits Assign and Call AST nodes to inspect as_view() registration calls."""

    def __init__(self, state: FlaskControllerState) -> None:
        self.state = state

    def visit(self, node: ASTNodeWrapper) -> None:
        raw = node.raw_node

        # Unwrap ast.Expr if needed
        if isinstance(raw, ast.Expr):
            raw = raw.value

        # Pattern 1: user_view = UserAPI.as_view("users")
        if isinstance(raw, ast.Assign):
            if isinstance(raw.value, ast.Call):
                self._inspect_as_view_call(raw.value)

        # Pattern 2: app.add_url_rule("/users", view_func=UserAPI.as_view("users"))
        elif isinstance(raw, ast.Call):
            self._inspect_as_view_call(raw)
            for keyword in raw.keywords:
                if isinstance(keyword.value, ast.Call):
                    self._inspect_as_view_call(keyword.value)

    def _inspect_as_view_call(self, call_node: ast.Call) -> None:
        if isinstance(call_node.func, ast.Attribute) and call_node.func.attr == "as_view":
            class_obj = call_node.func.value
            class_name = ""
            if isinstance(class_obj, ast.Name):
                class_name = class_obj.id
            elif isinstance(class_obj, ast.Attribute):
                class_name = class_obj.attr

            if class_name and call_node.args:
                arg0 = call_node.args[0]
                if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                    view_name = arg0.value
                    self.state.register_as_view(view_name, class_name)
