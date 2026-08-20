"""AST Visitor for session usage with strict semantic classification."""

from __future__ import annotations

import ast

from karsasec.framework.extractors.flask.auth.state import (
    AuthCandidate,
    FlaskAuthState,
    SessionCandidate,
)
from karsasec.framework.origin import Evidence
from karsasec.framework.parser.ast_adapter import ASTNodeWrapper


class FlaskSessionVisitor:
    """Visits Subscript, Call, and If AST nodes to classify Flask session usage."""

    IDENTITY_KEYS = {"user_id", "user", "username", "uid", "subject", "sub", "account_id"}
    AUTH_KEYS = {"authenticated", "logged_in", "auth_token", "token", "access_token"}
    ROLE_KEYS = {"role", "roles", "permissions", "is_admin"}

    def __init__(self, state: FlaskAuthState) -> None:
        self.state = state

    def visit(self, node: ASTNodeWrapper) -> None:
        raw = node.raw_node

        if isinstance(raw, ast.Subscript):
            self._check_subscript(raw, node)
        elif isinstance(raw, ast.Call):
            self._check_call(raw, node)
        elif isinstance(raw, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._check_function_access_control(raw, node)

    def _check_subscript(self, sub: ast.Subscript, node: ASTNodeWrapper) -> None:
        if not self._is_session_expr(sub.value):
            return

        key = self._extract_key(sub.slice)
        if not key:
            return

        classification = self._classify_key(key)
        evidence = Evidence(
            snippet=f"session['{key}']",
            rule_or_marker=f"session_key:{classification}",
            file_path=node.file_path,
            line=node.line,
        )
        cand = SessionCandidate(
            key=key,
            operation="ACCESS",
            classification=classification,
            file_path=node.file_path,
            line=node.line,
            evidence=(evidence,),
        )
        self.state.add_session_candidate(cand)

    def _check_call(self, call: ast.Call, node: ASTNodeWrapper) -> None:
        if isinstance(call.func, ast.Attribute) and call.func.attr == "get":
            if self._is_session_expr(call.func.value) and call.args:
                key = self._extract_key(call.args[0])
                if key:
                    classification = self._classify_key(key)
                    evidence = Evidence(
                        snippet=f"session.get('{key}')",
                        rule_or_marker=f"session_get:{classification}",
                        file_path=node.file_path,
                        line=node.line,
                    )
                    cand = SessionCandidate(
                        key=key,
                        operation="READ",
                        classification=classification,
                        file_path=node.file_path,
                        line=node.line,
                        evidence=(evidence,),
                    )
                    self.state.add_session_candidate(cand)

    def _check_function_access_control(
        self, func: ast.FunctionDef | ast.AsyncFunctionDef, node: ASTNodeWrapper
    ) -> None:
        # Check if function contains access-control logic checking session identity
        for stmt in func.body:
            if isinstance(stmt, ast.If):
                test_str = ast.unparse(stmt.test) if hasattr(ast, "unparse") else ""
                for key in self.IDENTITY_KEYS.union(self.AUTH_KEYS):
                    if key in test_str and ("session" in test_str or "flask.session" in test_str):
                        evidence = Evidence(
                            snippet=f"if '{key}' in/not in session:",
                            rule_or_marker="session_access_control",
                            file_path=node.file_path,
                            line=node.line,
                        )
                        auth_cand = AuthCandidate(
                            auth_type="SESSION",
                            provider="session",
                            scheme="session",
                            handler=func.name,
                            session_keys=(key,),
                            file_path=node.file_path,
                            line=node.line,
                            confidence=0.95,
                            evidence=(evidence,),
                        )
                        self.state.add_auth_candidate(auth_cand)

    def _classify_key(self, key: str) -> str:
        k = key.lower()
        if k in self.IDENTITY_KEYS:
            return "IDENTITY_SESSION"
        elif k in self.AUTH_KEYS:
            return "AUTH_SESSION"
        elif k in self.ROLE_KEYS:
            return "ROLE_SESSION"
        return "GENERIC_SESSION"

    def _is_session_expr(self, expr: ast.AST) -> bool:
        if isinstance(expr, ast.Name) and expr.id == "session":
            return True
        elif isinstance(expr, ast.Attribute) and expr.attr == "session":
            return isinstance(expr.value, ast.Name) and expr.value.id == "flask"
        return False

    def _extract_key(self, expr: ast.AST) -> str:
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            return expr.value
        return ""
