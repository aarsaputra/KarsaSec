"""AST Visitor for cookie usage with strict semantic classification."""

from __future__ import annotations

import ast

from karsasec.framework.extractors.flask.auth.state import (
    AuthCandidate,
    CookieCandidate,
    FlaskAuthState,
)
from karsasec.framework.origin import Evidence
from karsasec.framework.parser.ast_adapter import ASTNodeWrapper


class FlaskCookieVisitor:
    """Visits Call AST nodes to classify set_cookie and delete_cookie operations."""

    AUTH_COOKIE_NAMES = {
        "session_token",
        "auth_token",
        "access_token",
        "jwt",
        "remember_token",
        "auth",
        "token",
        "remember_me",
        "session",
    }

    def __init__(self, state: FlaskAuthState) -> None:
        self.state = state

    def visit(self, node: ASTNodeWrapper) -> None:
        raw = node.raw_node

        if isinstance(raw, ast.Call):
            self._visit_call(raw, node)

    def _visit_call(self, call: ast.Call, node: ASTNodeWrapper) -> None:
        if not isinstance(call.func, ast.Attribute):
            return

        method_name = call.func.attr
        if method_name in ("set_cookie", "delete_cookie"):
            if not call.args:
                return

            cookie_name = self._extract_cookie_name(call.args[0])
            if not cookie_name:
                return

            classification = self._classify_cookie(cookie_name)
            evidence = Evidence(
                snippet=f"{method_name}('{cookie_name}')",
                rule_or_marker=f"cookie_op:{classification}",
                file_path=node.file_path,
                line=node.line,
            )

            op_type = "SET" if method_name == "set_cookie" else "DELETE"
            cand = CookieCandidate(
                name=cookie_name,
                operation=op_type,
                classification=classification,
                file_path=node.file_path,
                line=node.line,
                evidence=(evidence,),
            )
            self.state.add_cookie_candidate(cand)

            if classification in ("AUTH_COOKIE", "REMEMBER_COOKIE", "SESSION_COOKIE"):
                auth_cand = AuthCandidate(
                    auth_type="COOKIE",
                    provider="custom",
                    scheme="cookie",
                    cookie_names=(cookie_name,),
                    file_path=node.file_path,
                    line=node.line,
                    confidence=0.90,
                    evidence=(evidence,),
                )
                self.state.add_auth_candidate(auth_cand)

    def _classify_cookie(self, cookie_name: str) -> str:
        name_lower = cookie_name.lower()
        if name_lower in ("remember_me", "remember", "remember_token"):
            return "REMEMBER_COOKIE"
        elif name_lower in ("session", "sessionid"):
            return "SESSION_COOKIE"
        elif any(term in name_lower for term in ("token", "auth", "jwt")):
            return "AUTH_COOKIE"
        return "GENERIC_COOKIE"

    def _extract_cookie_name(self, expr: ast.AST) -> str:
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            return expr.value
        return ""
