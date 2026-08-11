"""AST Visitor for Flask teardown_request and teardown_appcontext hooks."""

from __future__ import annotations

import ast

from karsasec.framework.extractors.flask.middleware.state import (
    FlaskMiddlewareState,
    MiddlewareCandidate,
)
from karsasec.framework.origin import Evidence
from karsasec.framework.parser.ast_adapter import ASTNodeWrapper


class FlaskTeardownVisitor:
    """Visits FunctionDef AST nodes to inspect teardown decorators."""

    TEARDOWN_MAP = {
        "teardown_request": "request_teardown",
        "teardown_appcontext": "application_teardown",
    }

    def __init__(self, state: FlaskMiddlewareState) -> None:
        self.state = state

    def visit(self, node: ASTNodeWrapper) -> None:
        raw = node.raw_node
        if not isinstance(raw, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return

        for dec in raw.decorator_list:
            dec_name = self._resolve_decorator_name(dec)
            if not dec_name:
                continue

            parts = dec_name.split(".")
            hook_func = parts[-1]
            if hook_func in self.TEARDOWN_MAP:
                owner = parts[0] if len(parts) > 1 else None
                is_bp = owner in self.state.blueprints or (owner and owner != "app" and "bp" in owner.lower())
                bp_name = self.state.blueprints.get(owner, owner) if is_bp else None

                evidence = Evidence(
                    snippet=f"@{dec_name}",
                    rule_or_marker=dec_name,
                    file_path=node.file_path,
                    line=node.line,
                )

                candidate = MiddlewareCandidate(
                    name=f"{owner or 'global'}.{raw.name}",
                    middleware_type="TEARDOWN",
                    handler=raw.name,
                    decorator=dec_name,
                    phase=self.TEARDOWN_MAP[hook_func],
                    file_path=node.file_path,
                    line=node.line,
                    blueprint=bp_name,
                    evidence=(evidence,),
                    confidence=0.95 if is_bp else 1.0,
                )
                self.state.add_middleware_candidate(candidate)

    def _resolve_decorator_name(self, dec: ast.AST) -> str:
        if isinstance(dec, ast.Name):
            return dec.id
        elif isinstance(dec, ast.Attribute):
            val_name = self._resolve_decorator_name(dec.value)
            return f"{val_name}.{dec.attr}" if val_name else dec.attr
        elif isinstance(dec, ast.Call):
            return self._resolve_decorator_name(dec.func)
        return ""
