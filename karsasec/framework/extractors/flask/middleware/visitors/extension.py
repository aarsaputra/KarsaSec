"""AST Visitor for Flask extension initializations (CORS, Limiter, LoginManager, Cache)."""

from __future__ import annotations

import ast

from karsasec.framework.extractors.flask.middleware.state import (
    ExtensionCandidate,
    FlaskMiddlewareState,
)
from karsasec.framework.origin import Evidence
from karsasec.framework.parser.ast_adapter import ASTNodeWrapper


class FlaskExtensionVisitor:
    """Visits Call AST nodes to inspect extension middleware instantiations."""

    KNOWN_EXTENSIONS = {
        "CORS", "FlaskCors",
        "Limiter", "FlaskLimiter",
        "LoginManager", "FlaskLogin",
        "Cache", "FlaskCache",
        "CSRFProtect", "FlaskWTF",
        "Session", "FlaskSession",
        "Bcrypt", "Talisman",
    }

    def __init__(self, state: FlaskMiddlewareState) -> None:
        self.state = state

    def visit(self, node: ASTNodeWrapper) -> None:
        raw = node.raw_node
        if not isinstance(raw, ast.Call):
            return

        ext_name, constructor, app_var = self._inspect_call(raw)
        if ext_name:
            evidence = Evidence(
                snippet=f"{constructor}({app_var})",
                rule_or_marker=ext_name,
                file_path=node.file_path,
                line=node.line,
            )

            candidate = ExtensionCandidate(
                extension_name=ext_name,
                constructor=constructor,
                application=app_var,
                file_path=node.file_path,
                line=node.line,
                evidence=(evidence,),
            )
            self.state.add_extension(candidate)

    def _inspect_call(self, call: ast.Call) -> tuple[str, str, str]:
        # Case 1: Direct instantiation e.g. CORS(app)
        if isinstance(call.func, ast.Name):
            func_name = call.func.id
            if func_name in self.KNOWN_EXTENSIONS or any(k in func_name for k in ("CORS", "Limiter", "Login", "Cache", "CSRF")):
                app_arg = self._resolve_arg(call.args[0]) if call.args else "app"
                return func_name, func_name, app_arg

        # Case 2: Attribute constructor e.g. flask_cors.CORS(app)
        elif isinstance(call.func, ast.Attribute):
            attr_name = call.func.attr
            if attr_name in self.KNOWN_EXTENSIONS or any(k in attr_name for k in ("CORS", "Limiter", "Login", "Cache", "CSRF")):
                app_arg = self._resolve_arg(call.args[0]) if call.args else "app"
                mod_name = self._resolve_arg(call.func.value)
                return attr_name, f"{mod_name}.{attr_name}", app_arg

            # Case 3: init_app pattern e.g. limiter.init_app(app)
            elif attr_name == "init_app":
                var_name = self._resolve_arg(call.func.value)
                app_arg = self._resolve_arg(call.args[0]) if call.args else "app"
                ext_type = var_name.capitalize()
                return ext_type, f"{var_name}.init_app", app_arg

        return "", "", ""

    def _resolve_arg(self, arg: ast.AST) -> str:
        if isinstance(arg, ast.Name):
            return arg.id
        elif isinstance(arg, ast.Attribute):
            val = self._resolve_arg(arg.value)
            return f"{val}.{arg.attr}" if val else arg.attr
        return "app"
