"""AST Visitor for Flask MethodView and View class controllers."""

from __future__ import annotations

import ast

from karsasec.framework.extractors.flask.controllers.state import (
    ControllerCandidate,
    FlaskControllerState,
    HandlerCandidate,
)
from karsasec.framework.origin import Evidence
from karsasec.framework.parser.ast_adapter import ASTNodeWrapper


class FlaskMethodViewVisitor:
    """Visits ClassDef AST nodes to detect MethodView and View subclasses and their method handlers."""

    HTTP_METHODS = {"get", "post", "put", "delete", "patch", "options", "head"}

    def __init__(self, state: FlaskControllerState) -> None:
        self.state = state

    def visit(self, node: ASTNodeWrapper) -> None:
        raw = node.raw_node
        if not isinstance(raw, ast.ClassDef):
            return

        is_view, parent_class = self._inspect_bases(raw)
        if not is_view:
            return

        class_name = raw.name
        handlers: list[str] = []
        confidence = 0.95 if parent_class == "MethodView" else 0.90

        evidence = Evidence(
            snippet=f"class {class_name}({parent_class}):",
            rule_or_marker="method_view",
            file_path=node.file_path,
            line=node.line,
        )

        for stmt in raw.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                method_name = stmt.name
                if method_name in self.HTTP_METHODS or method_name == "dispatch_request":
                    qual_handler = f"{class_name}.{method_name}"
                    handlers.append(qual_handler)

                    params = self._extract_parameters(stmt)
                    return_type = self._extract_return_type(stmt)
                    http_method = method_name.upper() if method_name in self.HTTP_METHODS else "ALL"

                    handler_cand = HandlerCandidate(
                        name=qual_handler,
                        qualified_name=qual_handler,
                        function_name=method_name,
                        parameters=tuple(params),
                        return_type=return_type,
                        http_methods=(http_method,),
                        file_path=node.file_path,
                        line=stmt.lineno,
                        confidence=confidence,
                        evidence=(evidence,),
                    )
                    self.state.add_handler(handler_cand)

        ctrl_cand = ControllerCandidate(
            name=class_name,
            qualified_name=class_name,
            controller_type="method_view" if parent_class == "MethodView" else "class_view",
            handlers=tuple(handlers),
            parent_class=parent_class,
            file_path=node.file_path,
            line=node.line,
            confidence=confidence,
            evidence=(evidence,),
        )
        self.state.add_controller(ctrl_cand)

    def _inspect_bases(self, class_node: ast.ClassDef) -> tuple[bool, str]:
        for base in class_node.bases:
            if isinstance(base, ast.Name) and base.id in {"MethodView", "View"}:
                return True, base.id
            elif isinstance(base, ast.Attribute) and base.attr in {"MethodView", "View"}:
                return True, base.attr
        return False, ""

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
