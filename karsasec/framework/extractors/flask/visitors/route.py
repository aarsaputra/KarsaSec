"""AST Visitor for standard Flask route decorators (@app.route, @app.get, @bp.route, etc.)."""

from __future__ import annotations

import ast

from karsasec.framework.extractors.flask.state import FlaskSemanticState, RawRouteRecord
from karsasec.framework.parser.ast_adapter import ASTNodeWrapper


class FlaskRouteVisitor:
    """Visits FunctionDef AST nodes to extract @app.route and shortcut route decorators."""

    def __init__(self, state: FlaskSemanticState) -> None:
        self.state = state

    def visit(self, node: ASTNodeWrapper) -> None:
        """Inspects FunctionDef or AsyncFunctionDef node for route decorators."""
        if node.node_type not in ("FunctionDef", "AsyncFunctionDef"):
            return

        raw: ast.FunctionDef | ast.AsyncFunctionDef = node.raw_node
        function_name = raw.name

        for decorator in raw.decorator_list:
            self._process_decorator(decorator, function_name, node)

    def _process_decorator(self, decorator: ast.AST, function_name: str, node: ASTNodeWrapper) -> None:
        call_node: ast.Call | None = None
        decorator_attr: str = ""

        if isinstance(decorator, ast.Call):
            call_node = decorator
            func = decorator.func
            if isinstance(func, ast.Attribute):
                decorator_attr = f"{self._get_expression_str(func.value)}.{func.attr}"
            elif isinstance(func, ast.Name):
                decorator_attr = func.id
        elif isinstance(decorator, ast.Attribute):
            decorator_attr = f"{self._get_expression_str(decorator.value)}.{decorator.attr}"
        elif isinstance(decorator, ast.Name):
            decorator_attr = decorator.id

        # Resolve alias if present
        resolved_target = self.state.resolve_decorator_target(decorator_attr)
        confidence = 1.0 if resolved_target == decorator_attr else 0.85

        # Check if target matches route decorator pattern (.route, .get, .post, .put, .delete, etc.)
        parts = resolved_target.split(".")
        method_shortcut: str | None = None
        is_route = False

        if len(parts) >= 2:
            var_name, action = parts[0], parts[-1]
            if action == "route":
                is_route = True
            elif action in ("get", "post", "put", "delete", "patch"):
                is_route = True
                method_shortcut = action.upper()
        elif resolved_target in ("route", "get", "post", "put", "delete"):
            is_route = True
            if resolved_target != "route":
                method_shortcut = resolved_target.upper()

        if not is_route or not call_node:
            return

        # Extract path argument (1st positional arg)
        path = "/"
        if call_node.args:
            path_arg = call_node.args[0]
            if isinstance(path_arg, ast.Constant) and isinstance(path_arg.value, str):
                path = path_arg.value

        # Extract methods argument
        methods: list[str] = [method_shortcut] if method_shortcut else ["GET"]
        endpoint = function_name

        for kw in call_node.keywords:
            if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                methods = []
                for elt in kw.value.elts:
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                        methods.append(elt.value.upper())
            elif kw.arg == "endpoint" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                endpoint = kw.value.value

        # Determine if bound to blueprint or app
        blueprint_name: str | None = None
        var_root = parts[0] if len(parts) >= 2 else "app"
        if var_root in self.state.blueprints or "bp" in var_root.lower() or "blueprint" in var_root.lower():
            blueprint_name = var_root

        # Capture evidence
        evidence_str = f"Detected Flask route decorator '{decorator_attr}' targeting '{path}'"

        rec = RawRouteRecord(
            path=path,
            methods=tuple(methods),
            endpoint=endpoint,
            handler_name=function_name,
            blueprint_name=blueprint_name,
            file_path=node.file_path,
            line=node.line,
            decorators=tuple(self._get_all_decorator_names(node.raw_node)),
            confidence=confidence,
            evidence=(evidence_str,),
        )
        self.state.routes.append(rec)

    def _get_expression_str(self, expr: ast.AST) -> str:
        if isinstance(expr, ast.Name):
            return expr.id
        if isinstance(expr, ast.Attribute):
            return f"{self._get_expression_str(expr.value)}.{expr.attr}"
        return "expr"

    def _get_all_decorator_names(self, func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
        names = []
        for d in func_node.decorator_list:
            if isinstance(d, ast.Call):
                if isinstance(d.func, ast.Name):
                    names.append(d.func.id)
                elif isinstance(d.func, ast.Attribute):
                    names.append(d.func.attr)
            elif isinstance(d, ast.Name):
                names.append(d.id)
            elif isinstance(d, ast.Attribute):
                names.append(d.attr)
        return names
