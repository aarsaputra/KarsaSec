"""AST Visitor for Flask-Login patterns (@login_required, login_user, logout_user, current_user)."""

from __future__ import annotations

import ast

from karsasec.framework.extractors.flask.auth.state import (
    AuthCandidate,
    FlaskAuthState,
)
from karsasec.framework.origin import Evidence
from karsasec.framework.parser.ast_adapter import ASTNodeWrapper


class FlaskLoginVisitor:
    """Visits FunctionDef and Call AST nodes for Flask-Login semantics."""

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
            if self._is_login_required(dec_name):
                evidence = Evidence(
                    snippet=f"@{dec_name}",
                    rule_or_marker="flask_login:login_required",
                    file_path=node.file_path,
                    line=node.line,
                )
                cand = AuthCandidate(
                    auth_type="FLASK_LOGIN",
                    provider="flask-login",
                    scheme="session",
                    handler=func.name,
                    decorator=dec_name,
                    file_path=node.file_path,
                    line=node.line,
                    confidence=1.0,
                    evidence=(evidence,),
                )
                self.state.add_auth_candidate(cand)

    def _visit_call(self, call: ast.Call, node: ASTNodeWrapper) -> None:
        func_name = self._resolve_name(call.func)
        if func_name in ("login_user", "logout_user"):
            evidence = Evidence(
                snippet=f"{func_name}(...)",
                rule_or_marker=f"flask_login:{func_name}",
                file_path=node.file_path,
                line=node.line,
            )
            remember_val = False
            for keyword in call.keywords:
                if keyword.arg == "remember":
                    if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                        remember_val = True

            cand = AuthCandidate(
                auth_type="FLASK_LOGIN",
                provider="flask-login",
                scheme="session",
                file_path=node.file_path,
                line=node.line,
                confidence=0.98,
                evidence=(evidence,),
                metadata={"operation": func_name, "remember": remember_val},
            )
            self.state.add_auth_candidate(cand)

    def _is_login_required(self, dec_name: str) -> bool:
        if not dec_name:
            return False
        base = dec_name.split(".")[-1]
        canonical = self.state.imports.get(base, base)
        canonical_base = canonical.split(".")[-1]
        return canonical_base == "login_required" or base == "login_required"

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
