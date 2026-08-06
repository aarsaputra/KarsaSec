"""Symbol DTO and SymbolGraph immutable models for Symbol Resolution Engine."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Symbol:
    """Represents a resolved variable, type, module, or method symbol."""

    id: str
    name: str
    qualified_name: str
    scope_name: str
    symbol_type: str  # e.g., "VARIABLE", "CLASS", "MODULE", "FUNCTION"
    file_path: str
    line_number: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "qualified_name": self.qualified_name,
            "scope_name": self.scope_name,
            "symbol_type": self.symbol_type,
            "file_path": self.file_path,
            "line_number": self.line_number,
        }


class SymbolGraph:
    """Immutable graph mapping code identifiers and AST nodes to resolved symbols."""

    def __init__(self) -> None:
        self._symbols: dict[str, Symbol] = {}
        self._identifier_map: dict[str, str] = {}  # node_id or location -> symbol_id
        self._imports: dict[str, str] = {}         # alias/name -> full import path

    def add_symbol(self, symbol: Symbol) -> None:
        """Registers a symbol in the graph."""
        self._symbols[symbol.id] = symbol

    def bind_identifier(self, identifier_key: str, symbol_id: str) -> None:
        """Binds a code location/node identifier to a resolved symbol ID."""
        self._identifier_map[identifier_key] = symbol_id

    def add_import(self, alias_or_name: str, full_module_path: str) -> None:
        """Registers an import or alias mapping."""
        self._imports[alias_or_name] = full_module_path

    def get_symbol_by_id(self, symbol_id: str) -> Symbol | None:
        """Retrieves a Symbol by ID."""
        return self._symbols.get(symbol_id)

    def resolve_identifier(self, identifier_key: str) -> Symbol | None:
        """Resolves an identifier key to its target Symbol."""
        symbol_id = self._identifier_map.get(identifier_key)
        if symbol_id:
            return self._symbols.get(symbol_id)
        return None

    def get_import_target(self, alias_or_name: str) -> str | None:
        """Resolves an alias or imported package name to full module path."""
        return self._imports.get(alias_or_name)

    @property
    def symbols(self) -> dict[str, Symbol]:
        """Returns map of symbol ID to Symbol."""
        return dict(self._symbols)

    def to_dict(self) -> dict[str, Any]:
        return {
            "symbols": {sid: s.to_dict() for sid, s in self._symbols.items()},
            "identifier_bindings": self._identifier_map,
            "imports": self._imports,
            "total_symbols": len(self._symbols),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
