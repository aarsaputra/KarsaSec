"""AST Visitor for Flask-JWT-Extended patterns (@jwt_required, create_access_token, etc.)."""

from __future__ import annotations

import ast

from karsasec.framework.extractors.flask.auth.state import (
    AuthCandidate,
    FlaskAuthState,
)
from karsasec.framework.origin import Evidence
from karsasec.framework.parser.ast_adapter import ASTNodeWrapper


class FlaskJWTVisitor:
    """Visits FunctionDef and Call AST nodes for Flask-JWT-Extended semantics."""

    JWT_CALLS = {"create_access_token", "create_refresh_token", "get_jwt_identity", "get_jwt"}

    def __init__(self, state: FlaskAuthState) -> None:
        self.state = state

    def visit(self, node: ASTNodeWrapper) -> None:
        raw = node.raw_node

        if isinstance(raw, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._visit_function_def(raw, node)
        elif isinstance(raw, ast.Call):
            self._visit_call(raw, node)

    def _visit_function_def(self, func: ast.FunctionDef | ast.AsyncFunctionDef, node: ASTNodeWrapper) -> None:
        for dec in func.decorator_list:
            dec_name = self._resolve_decorator_name(dec)
            if self._is_jwt_required(dec_name):
                optional = False
                refresh = False
                if isinstance(dec, ast.Call):
                    for kw in dec.keywords:
                        if kw.arg == "optional" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            optional = True
                        if kw.arg == "refresh" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            refresh = True

                evidence = Evidence(
                    snippet=f"@{dec_name}",
                    rule_or_marker="jwt:jwt_required",
                    file_path=node.file_path,
                    line=node.line,
                )
                cand = AuthCandidate(
                    auth_type="JWT",
                    provider="flask-jwt-extended",
                    scheme="jwt",
                    handler=func.name,
                    decorator=dec_name,
                    file_path=node.file_path,
                    line=node.line,
                    confidence=1.0,
                    evidence=(evidence,),
                    metadata={"optional": optional, "refresh": refresh},
                )
                self.state.add_auth_candidate(cand)

    def _visit_call(self, call: ast.Call, node: ASTNodeWrapper) -> None:
        func_name = self._resolve_name(call.func)
        base_name = func_name.split(".")[-1]
        canonical = self.state.imports.get(base_name, base_name)
        canonical_base = canonical.split(".")[-1]

        if canonical_base in self.JWT_CALLS or base_name in self.JWT_CALLS:
            evidence = Evidence(
                snippet=f"{func_name}(...)",
                rule_or_marker=f"jwt:{canonical_base}",
                file_path=node.file_path,
                line=node.line,
            )
            cand = AuthCandidate(
                auth_type="JWT",
                provider="flask-jwt-extended",
                scheme="jwt",
                file_path=node.file_path,
                line=node.line,
                confidence=0.98,
                evidence=(evidence,),
                metadata={"operation": canonical_base},
            )
            self.state.add_auth_candidate(cand)

    def _is_jwt_required(self, dec_name: str) -> bool:
        if not dec_name:
            return False
        base = dec_name.split(".")[-1]
        canonical = self.state.imports.get(base, base)
        canonical_base = canonical.split(".")[-1]
        return canonical_base == "jwt_required" or base == "jwt_required"

    def _resolve_decorator_name(self, dec: ast.AST) -> str:
        if isinstance(dec, ast.Name):
            return dec.id
        elif isinstance(dec, ast.Attribute):
            val = self._resolve_decorator_name(dec.value)
            return f"{val}.{dec.attr}" if val else dec.attr
        elif isinstance(dec, ast.Call):
            return self._resolve_decorator_name(dec.func)
        return ""

    def _resolve_name(self, expr: ast.AST) -> str:
        if isinstance(expr, ast.Name):
            return expr.id
        elif isinstance(expr, ast.Attribute):
            val = self._resolve_name(expr.value)
            return f"{val}.{expr.attr}" if val else expr.attr
        return ""
