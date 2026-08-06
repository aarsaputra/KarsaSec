"""Scope-aware semantic symbol definitions."""

from dataclasses import dataclass

from karsasec.semantic.scope import Scope


@dataclass(slots=True)
class SemanticSymbol:
    """Represents a bound symbol in a specific scope with semantic context."""
    name: str
    fully_qualified_name: str
    node_id: str
    scope: Scope
