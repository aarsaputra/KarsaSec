"""AST Visitor for Flask direct subscript and attribute config assignments."""

from __future__ import annotations

import ast
from typing import Any

from karsasec.framework.extractors.flask.config.classifier import SensitiveConfigClassifier
from karsasec.framework.extractors.flask.config.state import ConfigCandidate, FlaskConfigState
from karsasec.framework.origin import Evidence
from karsasec.framework.parser.ast_adapter import ASTNodeWrapper


class FlaskDirectConfigVisitor:
    """Visits Assign AST nodes to discover app.config['KEY'] = val and app.config.KEY = val."""

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

        if not isinstance(raw, ast.Assign):
            return

        for target in raw.targets:
            # Pattern 1: app.config['KEY'] = val or config['KEY'] = val
            if isinstance(target, ast.Subscript):
                if self._is_config_obj(target.value):
                    key_str = self._resolve_constant(target.slice)
                    if key_str:
                        val_res, is_dyn = self._resolve_value(raw.value)
                        category, is_sens = SensitiveConfigClassifier.classify(key_str)

                        evidence = Evidence(
                            snippet=f"app.config['{key_str}'] = ...",
                            rule_or_marker="direct_config_assign",
                            file_path=node.file_path,
                            line=node.line,
                        )

                        cand = ConfigCandidate(
                            key=key_str,
                            value=val_res,
                            source_type="direct_assign",
                            category=category,
                            file_path=node.file_path,
                            line=node.line,
                            confidence=1.0,
                            is_sensitive=is_sens,
                            is_dynamic=is_dyn,
                            evidence=(evidence,),
                        )
                        self.state.add_config(cand)

            # Pattern 2: app.config.KEY = val
            elif isinstance(target, ast.Attribute):
                if self._is_config_obj(target.value):
                    key_str = target.attr
                    val_res, is_dyn = self._resolve_value(raw.value)
                    category, is_sens = SensitiveConfigClassifier.classify(key_str)

                    evidence = Evidence(
                        snippet=f"app.config.{key_str} = ...",
                        rule_or_marker="attribute_config_assign",
                        file_path=node.file_path,
                        line=node.line,
                    )

                    cand = ConfigCandidate(
                        key=key_str,
                        value=val_res,
                        source_type="attribute_assign",
                        category=category,
                        file_path=node.file_path,
                        line=node.line,
                        confidence=0.98,
                        is_sensitive=is_sens,
                        is_dynamic=is_dyn,
                        evidence=(evidence,),
                    )
                    self.state.add_config(cand)

    def _resolve_constant(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None

    def _resolve_value(self, node: ast.AST) -> tuple[Any, bool]:
        if isinstance(node, ast.Constant):
            return node.value, False
        elif isinstance(node, ast.Name):
            return f"var:{node.id}", True
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                return f"call:{node.func.attr}()", True
            elif isinstance(node.func, ast.Name):
                return f"call:{node.func.id}()", True
        return "<dynamic>", True
