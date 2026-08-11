"""AST Visitor for environment variable lookups (os.environ, os.getenv, dotenv, decouple, django-environ)."""

from __future__ import annotations

import ast

from karsasec.framework.extractors.flask.config.classifier import SensitiveConfigClassifier
from karsasec.framework.extractors.flask.config.state import ConfigCandidate, EnvironmentCandidate, FlaskConfigState
from karsasec.framework.origin import Evidence
from karsasec.framework.parser.ast_adapter import ASTNodeWrapper


class FlaskEnvironmentVisitor:
    """Visits Call and Subscript AST nodes to discover environment variable lookups and dotenv loading."""

    def __init__(self, state: FlaskConfigState) -> None:
        self.state = state

    def visit(self, node: ASTNodeWrapper) -> None:
        raw = node.raw_node

        if isinstance(raw, ast.Expr):
            return

        # Pattern 1: os.getenv("SECRET_KEY", "dev") or os.environ.get("SECRET_KEY") or decouple.config("KEY")
        if isinstance(raw, ast.Call):
            func_str = self._resolve_func_name(raw.func)

            if func_str in {"os.getenv", "os.environ.get", "getenv", "config", "env"}:
                var_name = self._extract_first_arg_str(raw)
                default_val = self._extract_second_arg(raw) if len(raw.args) > 1 else None

                if var_name:
                    evidence = Evidence(
                        snippet=f"{func_str}('{var_name}')",
                        rule_or_marker="env_lookup",
                        file_path=node.file_path,
                        line=node.line,
                    )

                    env_cand = EnvironmentCandidate(
                        var_name=var_name,
                        default_value=default_val,
                        source=func_str,
                        file_path=node.file_path,
                        line=node.line,
                        confidence=0.85,
                        evidence=(evidence,),
                    )
                    self.state.add_env_var(env_cand)

                    category, is_sens = SensitiveConfigClassifier.classify(var_name)
                    cfg_cand = ConfigCandidate(
                        key=var_name,
                        value=f"env:{var_name}",
                        source_type="env_lookup",
                        category=category,
                        loader=func_str,
                        file_path=node.file_path,
                        line=node.line,
                        confidence=0.85,
                        is_sensitive=is_sens,
                        is_dynamic=True,
                        evidence=(evidence,),
                    )
                    self.state.add_config(cfg_cand)

            elif func_str in {"load_dotenv", "dotenv.load_dotenv"}:
                evidence = Evidence(
                    snippet="load_dotenv()",
                    rule_or_marker="dotenv_load",
                    file_path=node.file_path,
                    line=node.line,
                )
                cfg_cand = ConfigCandidate(
                    key="__DOTENV__:LOADED",
                    value=".env",
                    source_type="dotenv",
                    category="app",
                    loader="dotenv",
                    file_path=node.file_path,
                    line=node.line,
                    confidence=0.90,
                    is_sensitive=False,
                    is_dynamic=True,
                    evidence=(evidence,),
                )
                self.state.add_config(cfg_cand)

        # Pattern 2: os.environ["SECRET_KEY"]
        elif isinstance(raw, ast.Subscript):
            val_str = self._resolve_func_name(raw.value)
            if val_str == "os.environ":
                var_name = self._resolve_constant(raw.slice)
                if var_name:
                    evidence = Evidence(
                        snippet=f"os.environ['{var_name}']",
                        rule_or_marker="os_environ_subscript",
                        file_path=node.file_path,
                        line=node.line,
                    )
                    env_cand = EnvironmentCandidate(
                        var_name=var_name,
                        source="os.environ",
                        file_path=node.file_path,
                        line=node.line,
                        confidence=0.85,
                        evidence=(evidence,),
                    )
                    self.state.add_env_var(env_cand)

                    category, is_sens = SensitiveConfigClassifier.classify(var_name)
                    cfg_cand = ConfigCandidate(
                        key=var_name,
                        value=f"env:{var_name}",
                        source_type="env_lookup",
                        category=category,
                        loader="os.environ",
                        file_path=node.file_path,
                        line=node.line,
                        confidence=0.85,
                        is_sensitive=is_sens,
                        is_dynamic=True,
                        evidence=(evidence,),
                    )
                    self.state.add_config(cfg_cand)

    def _resolve_func_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            val = self._resolve_func_name(node.value)
            return f"{val}.{node.attr}" if val else node.attr
        return ""

    def _extract_first_arg_str(self, call_node: ast.Call) -> str | None:
        if call_node.args:
            return self._resolve_constant(call_node.args[0])
        return None

    def _extract_second_arg(self, call_node: ast.Call) -> str | None:
        if len(call_node.args) > 1:
            return self._resolve_constant(call_node.args[1])
        return None

    def _resolve_constant(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None
