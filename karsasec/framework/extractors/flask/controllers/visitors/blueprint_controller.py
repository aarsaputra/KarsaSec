"""AST Visitor for Flask Blueprint creation and route/controller bindings."""

from __future__ import annotations

import ast

from karsasec.framework.extractors.flask.controllers.state import FlaskControllerState
from karsasec.framework.parser.ast_adapter import ASTNodeWrapper


class FlaskBlueprintControllerVisitor:
    """Visits Assign and Call AST nodes to discover Blueprint definitions and add_url_rule calls."""

    def __init__(self, state: FlaskControllerState) -> None:
        self.state = state

    def visit(self, node: ASTNodeWrapper) -> None:
        raw = node.raw_node

        if isinstance(raw, ast.Expr):
            raw = raw.value

        # Pattern 1: api = Blueprint('api', __name__)
        if isinstance(raw, ast.Assign):
            if isinstance(raw.value, ast.Call):
                self._inspect_blueprint_instantiation(raw.targets, raw.value)

        # Pattern 2: app.add_url_rule(...) or bp.add_url_rule(...)
        elif isinstance(raw, ast.Call):
            self._inspect_add_url_rule(raw)

    def _inspect_blueprint_instantiation(self, targets: list[ast.expr], call_node: ast.Call) -> None:
        func_name = ""
        if isinstance(call_node.func, ast.Name):
            func_name = call_node.func.id
        elif isinstance(call_node.func, ast.Attribute):
            func_name = call_node.func.attr

        if func_name == "Blueprint":
            bp_name = ""
            if call_node.args and isinstance(call_node.args[0], ast.Constant) and isinstance(call_node.args[0].value, str):
                bp_name = call_node.args[0].value

            for target in targets:
                if isinstance(target, ast.Name):
                    var_name = target.id
                    self.state.register_blueprint(var_name, bp_name or var_name)

    def _inspect_add_url_rule(self, call_node: ast.Call) -> None:
        if isinstance(call_node.func, ast.Attribute) and call_node.func.attr == "add_url_rule":
            route_path = ""
            handler_name = ""

            if call_node.args and isinstance(call_node.args[0], ast.Constant) and isinstance(call_node.args[0].value, str):
                route_path = call_node.args[0].value

            for keyword in call_node.keywords:
                if keyword.arg == "view_func":
                    if isinstance(keyword.value, ast.Name):
                        handler_name = keyword.value.id
                    elif isinstance(keyword.value, ast.Attribute):
                        handler_name = keyword.value.attr
                    elif isinstance(keyword.value, ast.Call):
                        # Handle view_func=UserAPI.as_view("users")
                        if isinstance(keyword.value.func, ast.Attribute) and keyword.value.func.attr == "as_view":
                            if keyword.value.args and isinstance(keyword.value.args[0], ast.Constant):
                                handler_name = str(keyword.value.args[0].value)

            if route_path and handler_name:
                self.state.register_route_binding(handler_name, route_path)
