"""Scope management for semantic symbol resolution."""

from enum import Enum
from typing import Dict, Optional

class ScopeType(Enum):
    GLOBAL = "global"
    FUNCTION = "function"
    CLASS = "class"
    BLOCK = "block"
    LAMBDA = "lambda"

class Scope:
    """Represents a lexical scope in hierarchical scoping hierarchy."""

    __slots__ = ("scope_type", "parent", "bindings")

    def __init__(self, scope_type: ScopeType, parent: Optional["Scope"] = None) -> None:
        self.scope_type: ScopeType = scope_type
        self.parent: Optional[Scope] = parent
        self.bindings: Dict[str, str] = {}

    def define(self, name: str, symbol: str) -> None:
        """Binds a name to a fully qualified symbol or value in the current scope."""
        self.bindings[name] = symbol

    def lookup(self, name: str) -> Optional[str]:
        """Looks up a name in the current scope or ascends the parent scope chain."""
        if name in self.bindings:
            return self.bindings[name]
        if self.parent:
            return self.parent.lookup(name)
        return None
