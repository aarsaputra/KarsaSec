"""AST Visitor for Flask function-based controllers and handlers."""

from __future__ import annotations

import ast

from karsasec.framework.extractors.flask.controllers.state import (
    ControllerCandidate,
    FlaskControllerState,
    HandlerCandidate,
)
from karsasec.framework.origin import Evidence
from karsasec.framework.parser.ast_adapter import ASTNodeWrapper


class FlaskFunctionControllerVisitor:
    """Visits FunctionDef AST nodes to extract function-based controllers and parameters."""

    ROUTE_DECORATORS = {"route", "get", "post", "put", "delete", "patch"}

    def __init__(self, state: FlaskControllerState) -> None:
        self.state = state

    def visit(self, node: ASTNodeWrapper) -> None:
        raw = node.raw_node
        if not isinstance(raw, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return

        is_route, obj_name, route_path, http_methods = self._inspect_decorators(raw)
        if not is_route:
            return

        func_name = raw.name
        bp_name = self.state.blueprints.get(obj_name) if obj_name else None
        qual_name = f"{bp_name}.{func_name}" if bp_name else f"{obj_name}.{func_name}" if obj_name else func_name

        params = self._extract_parameters(raw)
        return_type = self._extract_return_type(raw)

        evidence = Evidence(
            snippet=f"def {func_name}(...)",
            rule_or_marker="route_handler",
            file_path=node.file_path,
            line=node.line,
        )

        handler_cand = HandlerCandidate(
            name=func_name,
            qualified_name=qual_name,
            function_name=func_name,
            parameters=tuple(params),
            return_type=return_type,
            http_methods=tuple(http_methods),
            file_path=node.file_path,
            line=node.line,
            confidence=1.0,
            evidence=(evidence,),
        )
        self.state.add_handler(handler_cand)

        if route_path:
            self.state.register_route_binding(func_name, route_path)

        routes_tuple = (route_path,) if route_path else ()
        ctrl_cand = ControllerCandidate(
            name=func_name,
            qualified_name=qual_name,
            controller_type="function_controller",
            handlers=(func_name,),
            file_path=node.file_path,
            line=node.line,
            blueprint=bp_name,
            confidence=1.0,
            routes=routes_tuple,
            evidence=(evidence,),
        )
        self.state.add_controller(ctrl_cand)

    def _inspect_decorators(
        self, func_node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> tuple[bool, str, str, list[str]]:
        is_route = False
        obj_name = ""
        route_path = ""
        http_methods: list[str] = []

        for decorator in func_node.decorator_list:
            call_node: ast.Call | None = None
            if isinstance(decorator, ast.Call):
                call_node = decorator
                func_expr = decorator.func
            else:
                func_expr = decorator

            if isinstance(func_expr, ast.Attribute):
                attr_name = func_expr.attr
                if attr_name in self.ROUTE_DECORATORS:
                    is_route = True
                    if isinstance(func_expr.value, ast.Name):
                        obj_name = func_expr.value.id

                    if attr_name in {"get", "post", "put", "delete", "patch"}:
                        http_methods.append(attr_name.upper())

                    if call_node:
                        if (
                            call_node.args
                            and isinstance(call_node.args[0], ast.Constant)
                            and isinstance(call_node.args[0].value, str)
                        ):
                            route_path = call_node.args[0].value

                        for keyword in call_node.keywords:
                            if keyword.arg == "methods":
                                if isinstance(keyword.value, (ast.List, ast.Tuple, ast.Set)):
                                    for elt in keyword.value.elts:
                                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                            http_methods.append(elt.value.upper())

        return is_route, obj_name, route_path, http_methods

    def _extract_parameters(self, func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
        params: list[str] = []
        for arg in func_node.args.args:
            if arg.arg in {"self", "cls"}:
                continue
            if arg.annotation:
                anno_str = self._resolve_annotation(arg.annotation)
                params.append(f"{arg.arg}:{anno_str}")
            else:
                params.append(arg.arg)
        return params

    def _extract_return_type(self, func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
        if func_node.returns:
            return self._resolve_annotation(func_node.returns)
        return "Any"

    def _resolve_annotation(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            val = self._resolve_annotation(node.value)
            return f"{val}.{node.attr}" if val else node.attr
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        elif isinstance(node, ast.Subscript):
            val = self._resolve_annotation(node.value)
            slice_val = self._resolve_annotation(node.slice)
            return f"{val}[{slice_val}]"
        return "Any"
