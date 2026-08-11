"""AST Visitor for class-based Flask middleware definitions."""

from __future__ import annotations

import ast

from karsasec.framework.extractors.flask.middleware.state import (
    FlaskMiddlewareState,
    MiddlewareCandidate,
)
from karsasec.framework.origin import Evidence
from karsasec.framework.parser.ast_adapter import ASTNodeWrapper


class FlaskClassMiddlewareVisitor:
    """Visits ClassDef AST nodes to inspect class-based middleware methods."""

    TARGET_METHODS = {"before_request", "after_request", "process_request", "process_response", "__call__"}

    def __init__(self, state: FlaskMiddlewareState) -> None:
        self.state = state

    def visit(self, node: ASTNodeWrapper) -> None:
        raw = node.raw_node
        if not isinstance(raw, ast.ClassDef):
            return

        class_name = raw.name

        # Check methods defined inside class
        for stmt in raw.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if stmt.name in self.TARGET_METHODS:
                    phase = "before_request"
                    if "after" in stmt.name or "response" in stmt.name:
                        phase = "after_response"

                    evidence = Evidence(
                        snippet=f"class {class_name}: def {stmt.name}(...)",
                        rule_or_marker=class_name,
                        file_path=node.file_path,
                        line=node.line,
                    )

                    candidate = MiddlewareCandidate(
                        name=f"{class_name}.{stmt.name}",
                        middleware_type="CLASS_MIDDLEWARE",
                        handler=f"{class_name}.{stmt.name}",
                        decorator="",
                        phase=phase,
                        file_path=node.file_path,
                        line=node.line,
                        evidence=(evidence,),
                        confidence=0.80,
                    )
                    self.state.add_class_middleware(candidate)
