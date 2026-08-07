"""SemanticSymbolTable maintaining multi-tier resolution from semantic symbols to CPG nodes."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("karsasec.framework.symbol_table")


@dataclass(frozen=True)
class SymbolBinding:
    """Immutable binding mapping a semantic symbol path to a target CPG Node ID."""
    symbol_path: str
    route_path: str | None = None
    handler_name: str | None = None
    controller_name: str | None = None
    class_name: str | None = None
    function_name: str | None = None
    cpg_node_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "symbol_path": self.symbol_path,
            "route_path": self.route_path,
            "handler_name": self.handler_name,
            "controller_name": self.controller_name,
            "class_name": self.class_name,
            "function_name": self.function_name,
            "cpg_node_id": self.cpg_node_id,
            "metadata": self.metadata,
        }


class SemanticSymbolTable:
    """Symbol Table managing resolution mapping: route -> handler -> controller -> class -> function -> CPG Node."""

    def __init__(self) -> None:
        self._forward_bindings: dict[str, SymbolBinding] = {}  # symbol_path -> SymbolBinding
        self._reverse_cpg_map: dict[str, list[SymbolBinding]] = {}  # cpg_node_id -> bindings
        self._handler_map: dict[str, list[SymbolBinding]] = {}  # handler_name -> bindings
        self._route_map: dict[str, list[SymbolBinding]] = {}  # route_path -> bindings

    def add_binding(self, binding: SymbolBinding) -> None:
        """Registers a symbol binding into the symbol table."""
        self._forward_bindings[binding.symbol_path] = binding

        if binding.cpg_node_id:
            self._reverse_cpg_map.setdefault(binding.cpg_node_id, []).append(binding)
        if binding.handler_name:
            self._handler_map.setdefault(binding.handler_name, []).append(binding)
        if binding.route_path:
            self._route_map.setdefault(binding.route_path, []).append(binding)

    def resolve(self, symbol_path: str) -> str | None:
        """Resolves a symbol path directly to a target CPG Node ID."""
        binding = self._forward_bindings.get(symbol_path)
        return binding.cpg_node_id if binding else None

    def lookup(self, symbol_path: str) -> SymbolBinding | None:
        """Retrieves SymbolBinding by symbol path."""
        return self._forward_bindings.get(symbol_path)

    def reverse_lookup(self, cpg_node_id: str) -> tuple[SymbolBinding, ...]:
        """Retrieves all SymbolBindings mapped to a specific CPG Node ID."""
        return tuple(self._reverse_cpg_map.get(cpg_node_id, []))

    def definition(self, handler_or_route: str) -> SymbolBinding | None:
        """Finds definition SymbolBinding for a handler name or route path."""
        if handler_or_route in self._forward_bindings:
            return self._forward_bindings[handler_or_route]

        by_route = self._route_map.get(handler_or_route)
        if by_route:
            return by_route[0]

        by_handler = self._handler_map.get(handler_or_route)
        if by_handler:
            return by_handler[0]

        return None

    def references(self, cpg_node_id: str) -> tuple[SymbolBinding, ...]:
        """Returns all symbol references pointing to a CPG Node ID."""
        return self.reverse_lookup(cpg_node_id)

    def list_bindings(self) -> tuple[SymbolBinding, ...]:
        """Returns tuple of all SymbolBindings in symbol table."""
        return tuple(self._forward_bindings.values())

    def clear(self) -> None:

        """Clears all bindings in symbol table."""
        self._forward_bindings.clear()
        self._reverse_cpg_map.clear()
        self._handler_map.clear()
        self._route_map.clear()


# Global default semantic symbol table instance
semantic_symbol_table = SemanticSymbolTable()
