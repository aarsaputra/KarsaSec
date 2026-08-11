"""AST Visitor for Flask app.config.update() and app.config.from_mapping() calls."""

from __future__ import annotations

import ast
from typing import Any

from karsasec.framework.extractors.flask.config.classifier import SensitiveConfigClassifier
from karsasec.framework.extractors.flask.config.state import ConfigCandidate, FlaskConfigState
from karsasec.framework.origin import Evidence
from karsasec.framework.parser.ast_adapter import ASTNodeWrapper


class FlaskConfigUpdateVisitor:
    """Visits Call AST nodes to discover app.config.update() and app.config.from_mapping()."""

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
            if method_name in {"update", "from_mapping"}:
                confidence = 0.98 if method_name == "update" else 0.95

                # 1. Keyword args: app.config.update(DEBUG=True, SECRET_KEY="abc")
                for kw in raw.keywords:
                    if kw.arg:
                        key_str = kw.arg
                        val_res, is_dyn = self._resolve_value(kw.value)
                        category, is_sens = SensitiveConfigClassifier.classify(key_str)

                        evidence = Evidence(
                            snippet=f"app.config.{method_name}({key_str}=...)",
                            rule_or_marker=f"config_{method_name}",
                            file_path=node.file_path,
                            line=node.line,
                        )

                        cand = ConfigCandidate(
                            key=key_str,
                            value=val_res,
                            source_type=method_name,
                            category=category,
                            file_path=node.file_path,
                            line=node.line,
                            confidence=confidence,
                            is_sensitive=is_sens,
                            is_dynamic=is_dyn,
                            evidence=(evidence,),
                        )
                        self.state.add_config(cand)

                # 2. Dict literal arg: app.config.update({"DEBUG": True})
                if raw.args and isinstance(raw.args[0], ast.Dict):
                    dict_node = raw.args[0]
                    for k_node, v_node in zip(dict_node.keys, dict_node.values, strict=False):
                        if k_node and isinstance(k_node, ast.Constant) and isinstance(k_node.value, str):
                            key_str = k_node.value
                            val_res, is_dyn = self._resolve_value(v_node)
                            category, is_sens = SensitiveConfigClassifier.classify(key_str)

                            evidence = Evidence(
                                snippet=f"app.config.{method_name}(\"{{'{key_str}': ...}}\")",
                                rule_or_marker=f"config_{method_name}_dict",
                                file_path=node.file_path,
                                line=node.line,
                            )

                            cand = ConfigCandidate(
                                key=key_str,
                                value=val_res,
                                source_type=method_name,
                                category=category,
                                file_path=node.file_path,
                                line=node.line,
                                confidence=confidence,
                                is_sensitive=is_sens,
                                is_dynamic=is_dyn,
                                evidence=(evidence,),
                            )
                            self.state.add_config(cand)

    def _resolve_value(self, node: ast.AST) -> tuple[Any, bool]:
        if isinstance(node, ast.Constant):
            return node.value, False
        elif isinstance(node, ast.Name):
            return f"var:{node.id}", True
        return "<dynamic>", True
