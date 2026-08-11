"""AST Visitor for detecting authentication managers (LoginManager, JWTManager, HTTPBasicAuth, etc.)."""

from __future__ import annotations

import ast

from karsasec.framework.extractors.flask.auth.state import (
    AuthManagerCandidate,
    FlaskAuthState,
)
from karsasec.framework.origin import Evidence
from karsasec.framework.parser.ast_adapter import ASTNodeWrapper


class FlaskAuthManagerVisitor:
    """Visits Assign and Call AST nodes to detect authentication manager initializations."""

    KNOWN_MANAGERS = {
        "LoginManager": ("LoginManager", "flask-login"),
        "JWTManager": ("JWTManager", "flask-jwt-extended"),
        "HTTPBasicAuth": ("HTTPBasicAuth", "flask-httpauth"),
        "HTTPTokenAuth": ("HTTPTokenAuth", "flask-httpauth"),
    }

    def __init__(self, state: FlaskAuthState) -> None:
        self.state = state

    def visit(self, node: ASTNodeWrapper) -> None:
        raw = node.raw_node

        if isinstance(raw, ast.Assign):
            self._handle_assign(raw, node)
        elif isinstance(raw, ast.Expr) and isinstance(raw.value, ast.Call):
            self._handle_call_expr(raw.value, node)

    def _handle_assign(self, assign: ast.Assign, node: ASTNodeWrapper) -> None:
        if not isinstance(assign.value, ast.Call):
            return

        call = assign.value
        func_name = self._resolve_name(call.func)
        manager_info = self._get_manager_info(func_name)
        if not manager_info:
            return

        manager_type, provider = manager_info
        app_var = ""
        if call.args:
            app_var = self._resolve_name(call.args[0])

        for target in assign.targets:
            var_name = self._resolve_name(target)
            if var_name:
                evidence = Evidence(
                    snippet=f"{var_name} = {func_name}(...)",
                    rule_or_marker=f"manager_init:{manager_type}",
                    file_path=node.file_path,
                    line=node.line,
                )
                candidate = AuthManagerCandidate(
                    manager_type=manager_type,
                    provider=provider,
                    variable_name=var_name,
                    application_var=app_var,
                    file_path=node.file_path,
                    line=node.line,
                    evidence=(evidence,),
                )
                self.state.register_manager(candidate)

    def _handle_call_expr(self, call: ast.Call, node: ASTNodeWrapper) -> None:
        # Detect login_manager.init_app(app) or jwt.init_app(app)
        if isinstance(call.func, ast.Attribute) and call.func.attr == "init_app":
            var_name = self._resolve_name(call.func.value)
            if var_name in self.state.managers:
                existing = self.state.managers[var_name]
                app_var = self._resolve_name(call.args[0]) if call.args else existing.application_var
                updated = AuthManagerCandidate(
                    manager_type=existing.manager_type,
                    provider=existing.provider,
                    variable_name=var_name,
                    application_var=app_var,
                    file_path=node.file_path,
                    line=node.line,
                    evidence=existing.evidence,
                )
                self.state.register_manager(updated)

    def _get_manager_info(self, func_name: str) -> tuple[str, str] | None:
        if not func_name:
            return None
        parts = func_name.split(".")
        base_name = parts[-1]

        # Check canonical import map if available
        canonical = self.state.imports.get(base_name, base_name)
        canonical_base = canonical.split(".")[-1]

        if canonical_base in self.KNOWN_MANAGERS:
            return self.KNOWN_MANAGERS[canonical_base]
        if base_name in self.KNOWN_MANAGERS:
            return self.KNOWN_MANAGERS[base_name]
        return None

    def _resolve_name(self, expr: ast.AST) -> str:
        if isinstance(expr, ast.Name):
            return expr.id
        elif isinstance(expr, ast.Attribute):
            val = self._resolve_name(expr.value)
            return f"{val}.{expr.attr}" if val else expr.attr
        return ""
