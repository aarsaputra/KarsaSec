"""AST Visitor for resolving auth module imports and aliases."""

from __future__ import annotations

import ast

from karsasec.framework.extractors.flask.auth.state import (
    FlaskAuthState,
    ProviderCandidate,
)
from karsasec.framework.origin import Evidence
from karsasec.framework.parser.ast_adapter import ASTNodeWrapper


class FlaskAuthImportResolverVisitor:
    """Visits Import and ImportFrom AST nodes to record imported auth symbols and providers."""

    KNOWN_MODULE_PROVIDERS = {
        "flask_login": "flask-login",
        "flask_jwt_extended": "flask-jwt-extended",
        "flask_httpauth": "flask-httpauth",
        "flask_security": "flask-security",
    }

    def __init__(self, state: FlaskAuthState) -> None:
        self.state = state

    def visit(self, node: ASTNodeWrapper) -> None:
        raw = node.raw_node

        if isinstance(raw, ast.Import):
            for alias in raw.names:
                mod_name = alias.name
                local_name = alias.asname or alias.name
                for known_mod, provider in self.KNOWN_MODULE_PROVIDERS.items():
                    if mod_name == known_mod or mod_name.startswith(f"{known_mod}."):
                        self.state.register_import(local_name, mod_name)
                        evidence = Evidence(
                            snippet=f"import {mod_name}" + (f" as {local_name}" if alias.asname else ""),
                            rule_or_marker=provider,
                            file_path=node.file_path,
                            line=node.line,
                        )
                        cand = ProviderCandidate(
                            name=provider,
                            symbol=local_name,
                            source_module=mod_name,
                            file_path=node.file_path,
                            line=node.line,
                            evidence=(evidence,),
                        )
                        self.state.register_provider(cand)

        elif isinstance(raw, ast.ImportFrom):
            mod_name = raw.module or ""
            for alias in raw.names:
                imported_symbol = alias.name
                local_name = alias.asname or imported_symbol
                canonical = f"{mod_name}.{imported_symbol}" if mod_name else imported_symbol
                self.state.register_import(local_name, canonical)

                for known_mod, provider in self.KNOWN_MODULE_PROVIDERS.items():
                    if mod_name == known_mod or mod_name.startswith(f"{known_mod}."):
                        evidence = Evidence(
                            snippet=f"from {mod_name} import {imported_symbol}" + (f" as {local_name}" if alias.asname else ""),
                            rule_or_marker=provider,
                            file_path=node.file_path,
                            line=node.line,
                        )
                        cand = ProviderCandidate(
                            name=provider,
                            symbol=local_name,
                            source_module=canonical,
                            file_path=node.file_path,
                            line=node.line,
                            evidence=(evidence,),
                        )
                        self.state.register_provider(cand)
