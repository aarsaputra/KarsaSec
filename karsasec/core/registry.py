"""Component Registry for registering Parsers, Rules, and AI Adapters."""

from typing import Any, Generic, TypeVar

T = TypeVar("T")

class ComponentRegistry(Generic[T]):
    """Registry pattern for dynamically loaded extension plugins."""

    def __init__(self, registry_name: str) -> None:
        self.name = registry_name
        self._components: dict[str, type[T]] = {}

    def register(self, key: str, component_cls: type[T]) -> None:
        """Registers a component class under a string key."""
        self._components[key.lower()] = component_cls

    def get(self, key: str) -> type[T] | None:
        """Retrieves a registered component class by key."""
        return self._components.get(key.lower())

    def list_keys(self) -> list[str]:
        """Lists all registered component keys."""
        return list(self._components.keys())

    def clear(self) -> None:
        """Clears registered components."""
        self._components.clear()

# Global registry for pluggable components such as hybrid RAG services.
rag_registry: ComponentRegistry[Any] = ComponentRegistry("RAGComponents")
