"""AST Visitor for add_url_rule calls and Flask application factory patterns."""

from __future__ import annotations

import ast

from karsasec.framework.extractors.flask.state import FlaskSemanticState, RawRouteRecord
from karsasec.framework.parser.ast_adapter import ASTNodeWrapper


class FlaskCallVisitor:
    """Visits Call and FunctionDef nodes to extract add_url_rule and create_app factory routes."""

    def __init__(self, state: FlaskSemanticState) -> None:
        self.state = state

    def visit(self, node: ASTNodeWrapper) -> None:
        """Inspects Call nodes for add_url_rule."""
        raw = node.raw_node

        if isinstance(raw, ast.Call):
            self._check_add_url_rule(raw, node)


    def _check_add_url_rule(self, call_node: ast.Call, node: ASTNodeWrapper) -> None:
        func = call_node.func
        if not isinstance(func, ast.Attribute) or func.attr != "add_url_rule":
            return

        if len(call_node.args) < 1:
            return


        # 1st arg: rule/path
        path = "/"
        rule_arg = call_node.args[0]
        if isinstance(rule_arg, ast.Constant) and isinstance(rule_arg.value, str):
            path = rule_arg.value

        # 2nd arg: endpoint or view_func
        handler_name = ""
        endpoint = ""
        if len(call_node.args) >= 2:
            view_func_arg = call_node.args[1]
            if isinstance(view_func_arg, ast.Constant) and isinstance(view_func_arg.value, str):
                endpoint = view_func_arg.value
            elif isinstance(view_func_arg, ast.Name):
                handler_name = view_func_arg.id


        # Check view_func kwarg or 3rd arg
        if len(call_node.args) >= 3 and not handler_name:
            arg3 = call_node.args[2]
            if isinstance(arg3, ast.Name):
                handler_name = arg3.id
            elif isinstance(arg3, ast.Attribute):
                handler_name = f"{arg3.value.id}.{arg3.attr}" if isinstance(arg3.value, ast.Name) else arg3.attr

        # Check methods kwarg
        methods: list[str] = ["GET"]
        for kw in call_node.keywords:
            if kw.arg == "view_func":
                if isinstance(kw.value, ast.Name):
                    handler_name = kw.value.id
                elif isinstance(kw.value, ast.Attribute):
                    val = kw.value.value
                    val_str = val.id if isinstance(val, ast.Name) else "attr"
                    handler_name = f"{val_str}.{kw.value.attr}"
                elif isinstance(kw.value, ast.Call) and isinstance(kw.value.func, ast.Attribute):
                    # view_func=UserAPI.as_view('user_api')
                    val = kw.value.func.value
                    handler_name = val.id if isinstance(val, ast.Name) else "ViewClass"

            elif kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                methods = []
                for elt in kw.value.elts:
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                        methods.append(elt.value.upper())
            elif kw.arg == "endpoint" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                endpoint = kw.value.value

        if not handler_name:
            handler_name = endpoint or "url_rule_handler"

        rec = RawRouteRecord(
            path=path,
            methods=tuple(methods),
            endpoint=endpoint or handler_name,
            handler_name=handler_name,
            file_path=node.file_path,
            line=node.line,
            confidence=1.0,
            evidence=(f"Detected add_url_rule for '{path}' calling '{handler_name}'",),
            is_add_url_rule=True,
        )
        self.state.routes.append(rec)
