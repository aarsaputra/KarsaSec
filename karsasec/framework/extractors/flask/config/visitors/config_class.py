"""AST Visitor for Flask configuration classes (e.g. Config, ProductionConfig, DevelopmentConfig)."""

from __future__ import annotations

import ast
from typing import Any

from karsasec.framework.extractors.flask.config.classifier import SensitiveConfigClassifier
from karsasec.framework.extractors.flask.config.state import (
    ConfigCandidate,
    ConfigClassCandidate,
    FlaskConfigState,
)
from karsasec.framework.origin import Evidence
from karsasec.framework.parser.ast_adapter import ASTNodeWrapper


class FlaskConfigClassVisitor:
    """Visits ClassDef AST nodes to discover configuration classes and attribute settings."""

    CONFIG_KEYWORDS = {"Config", "Configuration", "Settings"}

    def __init__(self, state: FlaskConfigState) -> None:
        self.state = state

    def visit(self, node: ASTNodeWrapper) -> None:
        raw = node.raw_node

        if not isinstance(raw, ast.ClassDef):
            return

        class_name = raw.name
        is_config_cls = any(kw in class_name for kw in self.CONFIG_KEYWORDS)
        parent_class = self._resolve_parent_class(raw)

        if not is_config_cls and not parent_class:
            return

        settings: list[tuple[str, Any]] = []
        evidence = Evidence(
            snippet=f"class {class_name}:",
            rule_or_marker="config_class",
            file_path=node.file_path,
            line=node.line,
        )

        for stmt in raw.body:
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        key_str = target.id
                        if key_str.isupper():
                            val_res = self._resolve_constant(stmt.value)
                            settings.append((key_str, val_res))

                            category, is_sens = SensitiveConfigClassifier.classify(key_str)
                            cand = ConfigCandidate(
                                key=key_str,
                                value=val_res,
                                source_type="config_class",
                                category=category,
                                loader=class_name,
                                file_path=node.file_path,
                                line=stmt.lineno,
                                confidence=0.90,
                                is_sensitive=is_sens,
                                is_dynamic=False,
                                evidence=(evidence,),
                            )
                            self.state.add_config(cand)

        cls_cand = ConfigClassCandidate(
            class_name=class_name,
            parent_class=parent_class,
            settings=tuple(settings),
            file_path=node.file_path,
            line=node.line,
            confidence=0.90,
            evidence=(evidence,),
        )
        self.state.add_config_class(cls_cand)

    def _resolve_parent_class(self, class_node: ast.ClassDef) -> str | None:
        for base in class_node.bases:
            if isinstance(base, ast.Name):
                return base.id
            elif isinstance(base, ast.Attribute):
                return base.attr
        return None

    def _resolve_constant(self, node: ast.AST) -> Any:
        if isinstance(node, ast.Constant):
            return node.value
        elif isinstance(node, ast.Name):
            return f"var:{node.id}"
        return "<dynamic>"
