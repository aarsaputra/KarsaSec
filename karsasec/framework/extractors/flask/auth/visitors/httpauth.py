"""AST Visitor for Flask-HTTPAuth patterns (@auth.login_required, verify_password, etc.)."""

from __future__ import annotations

import ast

from karsasec.framework.extractors.flask.auth.state import (
    AuthCandidate,
    FlaskAuthState,
)
from karsasec.framework.origin import Evidence
from karsasec.framework.parser.ast_adapter import ASTNodeWrapper


class FlaskHTTPAuthVisitor:
    """Visits FunctionDef AST nodes for Flask-HTTPAuth decorator patterns."""

    HTTPAUTH_HOOKS = {"login_required", "verify_password", "verify_token", "get_user_roles"}

    def __init__(self, state: FlaskAuthState) -> None:
        self.state = state

    def visit(self, node: ASTNodeWrapper) -> None:
        raw = node.raw_node

        if isinstance(raw, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._visit_function_def(raw, node)

    def _visit_function_def(self, func: ast.FunctionDef | ast.AsyncFunctionDef, node: ASTNodeWrapper) -> None:
        for dec in func.decorator_list:
            dec_name = self._resolve_decorator_name(dec)
            if not dec_name:
                continue

            parts = dec_name.split(".")
            var_name = parts[0] if len(parts) > 1 else ""
            attr_name = parts[-1]

            # Check if var_name is a registered manager or attribute is a known httpauth hook
            manager_cand = self.state.managers.get(var_name)
            is_httpauth = False
            scheme = "basic"
            provider = "flask-httpauth"

            if manager_cand and manager_cand.provider == "flask-httpauth":
                is_httpauth = True
                scheme = "token" if "Token" in manager_cand.manager_type else "basic"
            elif attr_name in self.HTTPAUTH_HOOKS and var_name and var_name in ("auth", "basic_auth", "token_auth", "http_auth"):
                is_httpauth = True
                if "token" in var_name:
                    scheme = "token"

            if is_httpauth:
                evidence = Evidence(
                    snippet=f"@{dec_name}",
                    rule_or_marker=f"httpauth:{attr_name}",
                    file_path=node.file_path,
                    line=node.line,
                )
                auth_type = "BASIC_AUTH" if scheme == "basic" else "TOKEN"
                cand = AuthCandidate(
                    auth_type=auth_type,
                    provider=provider,
                    scheme=scheme,
                    handler=func.name,
                    decorator=dec_name,
                    manager=var_name,
                    file_path=node.file_path,
                    line=node.line,
                    confidence=1.0 if manager_cand else 0.95,
                    evidence=(evidence,),
                    metadata={"hook": attr_name},
                )
                self.state.add_auth_candidate(cand)

    def _resolve_decorator_name(self, dec: ast.AST) -> str:
        if isinstance(dec, ast.Name):
            return dec.id
        elif isinstance(dec, ast.Attribute):
            val = self._resolve_decorator_name(dec.value)
            return f"{val}.{dec.attr}" if val else dec.attr
        elif isinstance(dec, ast.Call):
            return self._resolve_decorator_name(dec.func)
        return ""
