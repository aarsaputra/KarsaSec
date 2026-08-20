"""Alias tracking and resolution engine."""


class AliasTracker:
    """Tracks variable references and resolves aliased symbols transitively."""

    def __init__(self) -> None:
        self.aliases: dict[str, str] = {}

    def register_alias(self, alias_name: str, target: str) -> None:
        """Registers a local name mapping to a target symbol or variable name."""
        self.aliases[alias_name] = target

    def resolve(self, name: str, visited: set[str] | None = None) -> str:
        """Resolves a name transitively to its root symbol, avoiding cycles."""
        if visited is None:
            visited = set()

        if name in visited:
            return name  # Break cycle

        visited.add(name)
        if name in self.aliases:
            return self.resolve(self.aliases[name], visited)
        return name
