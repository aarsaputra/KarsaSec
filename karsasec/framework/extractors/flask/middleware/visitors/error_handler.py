"""AST Visitor for Flask errorhandler decorators."""

from __future__ import annotations

import ast

from karsasec.framework.extractors.flask.middleware.state import (
    ErrorHandlerCandidate,
    FlaskMiddlewareState,
)
from karsasec.framework.origin import Evidence
from karsasec.framework.parser.ast_adapter import ASTNodeWrapper


class FlaskErrorHandlerVisitor:
    """Visits FunctionDef AST nodes to inspect errorhandler decorators."""

    def __init__(self, state: FlaskMiddlewareState) -> None:
        self.state = state

    def visit(self, node: ASTNodeWrapper) -> None:
        raw = node.raw_node
        if not isinstance(raw, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return

        for dec in raw.decorator_list:
            if not isinstance(dec, ast.Call):
                continue

            dec_name = self._resolve_decorator_name(dec.func)
            if not dec_name or not dec_name.endswith(".errorhandler") and dec_name != "errorhandler":
                continue

            parts = dec_name.split(".")
            owner = parts[0] if len(parts) > 1 else None
            bp_name = self.state.blueprints.get(owner, owner) if owner and owner != "app" else None

            status_code: int | None = None
            exception_type = "Exception"

            if dec.args:
                arg0 = dec.args[0]
                if isinstance(arg0, ast.Constant) and isinstance(arg0.value, int):
                    status_code = arg0.value
                    exception_type = f"HTTP_{status_code}"
                elif isinstance(arg0, ast.Name):
                    exception_type = arg0.id
                elif isinstance(arg0, ast.Attribute):
                    exception_type = arg0.attr

            evidence = Evidence(
                snippet=f"@{dec_name}(...)",
                rule_or_marker=dec_name,
                file_path=node.file_path,
                line=node.line,
            )

            candidate = ErrorHandlerCandidate(
                exception_type=exception_type,
                status_code=status_code,
                handler=raw.name,
                file_path=node.file_path,
                line=node.line,
                blueprint=bp_name,
                evidence=(evidence,),
            )
            self.state.add_error_handler(candidate)

    def _resolve_decorator_name(self, dec: ast.AST) -> str:
        if isinstance(dec, ast.Name):
            return dec.id
        elif isinstance(dec, ast.Attribute):
            val_name = self._resolve_decorator_name(dec.value)
            return f"{val_name}.{dec.attr}" if val_name else dec.attr
        return ""
