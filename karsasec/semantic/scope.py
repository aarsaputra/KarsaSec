"""Scope management for semantic symbol resolution."""

import weakref
from enum import Enum
from typing import Optional


class ScopeType(Enum):
    GLOBAL = "global"
    FUNCTION = "function"
    CLASS = "class"
    BLOCK = "block"
    LAMBDA = "lambda"

class Scope:
    """Represents a lexical scope in hierarchical scoping hierarchy."""

    __slots__ = ("scope_type", "_parent_ref", "bindings", "__weakref__")

    def __init__(self, scope_type: ScopeType, parent: Optional["Scope"] = None) -> None:
        self.scope_type: ScopeType = scope_type
        self._parent_ref = weakref.ref(parent) if parent is not None else None
        self.bindings: dict[str, str] = {}

    @property
    def parent(self) -> Optional["Scope"]:
        """Retrieve parent scope if it hasn't been garbage collected."""
        return self._parent_ref() if self._parent_ref is not None else None

    @parent.setter
    def parent(self, value: Optional["Scope"]) -> None:
        """Set parent scope using a weak reference."""
        self._parent_ref = weakref.ref(value) if value is not None else None

    def define(self, name: str, symbol: str) -> None:
        """Binds a name to a fully qualified symbol or value in the current scope."""
        self.bindings[name] = symbol

    def lookup(self, name: str) -> str | None:
        """Looks up a name in the current scope or ascends the parent scope chain."""
        if name in self.bindings:
            return self.bindings[name]
        p = self.parent
        if p:
            return p.lookup(name)
        return None
