"""Alias tracking and resolution engine."""

from typing import Dict, Optional, Set

class AliasTracker:
    """Tracks variable references and resolves aliased symbols transitively."""

    def __init__(self) -> None:
        self.aliases: Dict[str, str] = {}

    def register_alias(self, alias_name: str, target: str) -> None:
        """Registers a local name mapping to a target symbol or variable name."""
        self.aliases[alias_name] = target

    def resolve(self, name: str, visited: Optional[Set[str]] = None) -> str:
        """Resolves a name transitively to its root symbol, avoiding cycles."""
        if visited is None:
            visited = set()

        if name in visited:
            return name  # Break cycle

        visited.add(name)
        if name in self.aliases:
            return self.resolve(self.aliases[name], visited)
        return name
