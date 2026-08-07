"""FrameworkResolver module for resolving module import aliases (e.g. 'import flask as f')."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any


class FrameworkResolver:
    """Resolves framework module import aliases and symbol bindings from AST and IR nodes."""

    def __init__(self) -> None:
        self._aliases: dict[str, str] = {}  # alias_name -> real_module_name

    def register_alias(self, alias: str, target_module: str) -> None:
        """Explicitly registers an alias mapping."""
        self._aliases[alias] = target_module

    def resolve_symbol(self, symbol_name: str) -> str:
        """Resolves a symbol or alias to its target module name."""
        return self._aliases.get(symbol_name, symbol_name)

    def extract_aliases_from_ast(self, file_nodes: Sequence[Any]) -> dict[str, str]:
        """Scans AST FileNodes to extract import alias statements across languages."""
        found: dict[str, str] = {}
        for fn in file_nodes:
            if not hasattr(fn, "nodes_map"):
                continue
            for node in fn.nodes_map.values():
                node_type = getattr(node, "node_type", "").lower()
                # Handle Python import_from / import_statement / alias
                if "import" in node_type or "use" in node_type or "require" in node_type:
                    raw_text = getattr(node, "text", "") or getattr(node, "name", "")
                    if " as " in raw_text:
                        parts = raw_text.split(" as ")
                        if len(parts) == 2:
                            real_mod = parts[0].strip().split()[-1]
                            alias = parts[1].strip().split()[0]
                            found[alias] = real_mod
                            self.register_alias(alias, real_mod)
        return found

    def is_alias_of(self, candidate: str, target_module: str) -> bool:
        """Returns True if candidate maps to or matches target_module."""
        resolved = self.resolve_symbol(candidate)
        return target_module.lower() in resolved.lower() or candidate.lower() in target_module.lower()
