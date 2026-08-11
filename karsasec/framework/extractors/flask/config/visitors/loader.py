"""AST Visitor for Flask config loader methods (from_object, from_pyfile, from_envvar, from_prefixed_env, from_file)."""

from __future__ import annotations

import ast

from karsasec.framework.extractors.flask.config.state import ConfigCandidate, FlaskConfigState
from karsasec.framework.origin import Evidence
from karsasec.framework.parser.ast_adapter import ASTNodeWrapper


class FlaskConfigLoaderVisitor:
    """Visits Call AST nodes to discover app.config.from_* loader calls."""

    LOADER_METHODS = {"from_object", "from_pyfile", "from_envvar", "from_file", "from_prefixed_env"}

    def __init__(self, state: FlaskConfigState) -> None:
        self.state = state

    def _is_config_obj(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Attribute) and node.attr == "config":
            return True
        if isinstance(node, ast.Name) and node.id in {"config", "app_config"}:
            return True
        return False

    def visit(self, node: ASTNodeWrapper) -> None:
        raw = node.raw_node

        if isinstance(raw, ast.Expr):
            return

        if not isinstance(raw, ast.Call):
            return

        if isinstance(raw.func, ast.Attribute) and self._is_config_obj(raw.func.value):
            method_name = raw.func.attr
            if method_name in self.LOADER_METHODS:
                loader_target = self._resolve_arg_target(raw)

                evidence = Evidence(
                    snippet=f"app.config.{method_name}({loader_target})",
                    rule_or_marker=f"config_loader_{method_name}",
                    file_path=node.file_path,
                    line=node.line,
                )

                cand = ConfigCandidate(
                    key=f"__LOADER__:{method_name.upper()}",
                    value=loader_target,
                    source_type=method_name,
                    category="app",
                    loader=method_name,
                    file_path=node.file_path,
                    line=node.line,
                    confidence=0.90 if method_name == "from_object" else 0.85,
                    is_sensitive=False,
                    is_dynamic=True,
                    evidence=(evidence,),
                )
                self.state.add_config(cand)

    def _resolve_arg_target(self, call_node: ast.Call) -> str:
        if call_node.args:
            arg0 = call_node.args[0]
            if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                return arg0.value
            elif isinstance(arg0, ast.Name):
                return arg0.id
            elif isinstance(arg0, ast.Attribute):
                return f"{self._resolve_attr_path(arg0)}"
        return "<unknown>"

    def _resolve_attr_path(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            val = self._resolve_attr_path(node.value)
            return f"{val}.{node.attr}" if val else node.attr
        return ""
