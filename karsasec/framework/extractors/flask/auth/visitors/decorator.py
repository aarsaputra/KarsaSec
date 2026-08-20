"""AST Visitor for custom decorator analysis using evidence-based wrapper inspection."""

from __future__ import annotations

import ast

from karsasec.framework.extractors.flask.auth.state import (
    AuthCandidate,
    DecoratorCandidate,
    FlaskAuthState,
)
from karsasec.framework.origin import Evidence
from karsasec.framework.parser.ast_adapter import ASTNodeWrapper


class FlaskCustomDecoratorVisitor:
    """Visits FunctionDef AST nodes to inspect decorator wrappers for auth evidence."""

    AUTH_MARKERS = {
        "current_user",
        "is_authenticated",
        "login_required",
        "jwt_required",
        "verify_password",
        "verify_token",
        "is_admin",
        "abort(401)",
        "abort(403)",
    }

    def __init__(self, state: FlaskAuthState) -> None:
        self.state = state

    def visit(self, node: ASTNodeWrapper) -> None:
        raw = node.raw_node

        if isinstance(raw, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._inspect_function_def(raw, node)

    def _inspect_function_def(self, func: ast.FunctionDef | ast.AsyncFunctionDef, node: ASTNodeWrapper) -> None:
        # Check if function takes a single argument 'fn' or 'func' (decorator signature)
        arg_names = [arg.arg for arg in func.args.args]
        if not arg_names or arg_names[0] not in ("fn", "func", "f"):
            return

        # Unparse body or inspect nodes to find inner wrapper and auth markers
        body_code = ast.unparse(func) if hasattr(ast, "unparse") else ""
        found_markers: list[str] = []

        for marker in self.AUTH_MARKERS:
            if marker in body_code:
                found_markers.append(marker)

        if "session" in body_code and ("user" in body_code or "auth" in body_code):
            found_markers.append("session_auth")

        if found_markers:
            wrapper_name = self._find_wrapper_name(func)
            evidence = Evidence(
                snippet=f"def {func.name}(...): wrapper with {','.join(found_markers)}",
                rule_or_marker=f"custom_decorator_evidence:{','.join(found_markers)}",
                file_path=node.file_path,
                line=node.line,
            )
            cand = DecoratorCandidate(
                name=func.name,
                func_name=func.name,
                wrapper_name=wrapper_name or "wrapper",
                is_auth_related=True,
                auth_evidence_type=",".join(found_markers),
                file_path=node.file_path,
                line=node.line,
                confidence=0.85,
                evidence=(evidence,),
            )
            self.state.add_decorator_candidate(cand)

            # Register auth candidate for handlers using this decorator
            auth_cand = AuthCandidate(
                auth_type="CUSTOM_DECORATOR",
                provider="custom",
                scheme="custom",
                decorator=func.name,
                file_path=node.file_path,
                line=node.line,
                confidence=0.85,
                evidence=(evidence,),
            )
            self.state.add_auth_candidate(auth_cand)

    def _find_wrapper_name(self, func: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
        for stmt in func.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return stmt.name
        return ""
