"""Dependency Injection Container for managing application components."""

import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

from karsasec.core.registry import rag_registry

T = TypeVar("T")

class Container:
    """Simple lightweight Dependency Injection (IoC) Container with thread safety."""

    def __init__(self) -> None:
        self._services: dict[type[Any], Any] = {}
        self._factories: dict[type[Any], Callable[[], Any]] = {}
        self._lock = threading.Lock()

    def register_singleton(self, interface: type[T], instance: T) -> None:
        """Registers a singleton instance for a given type interface."""
        with self._lock:
            self._services[interface] = instance

    def register_factory(self, interface: type[T], factory: Callable[[], T]) -> None:
        """Registers a factory callable that creates a new instance on resolve."""
        with self._lock:
            self._factories[interface] = factory

    def register_rag_service(self, corpus_root: Path, force_rebuild: bool = False) -> None:
        """Registers the RAGService singleton built from a local corpus path."""
        from karsasec.rag.service import RAGService

        service = RAGService.from_directory(corpus_root, force_rebuild=force_rebuild)
        self.register_singleton(RAGService, service)
        rag_registry.register(RAGService.__name__, RAGService)

    def resolve(self, interface: type[T]) -> T:
        """Resolves a registered service or raises KeyError if unregistered."""
        with self._lock:
            if interface in self._services:
                return self._services[interface]  # type: ignore[no-any-return]

            if interface in self._factories:
                return self._factories[interface]()  # type: ignore[no-any-return]

        raise KeyError(f"Service '{interface.__name__}' is not registered in the Container.")

    def reset(self) -> None:
        """Resets all registered services."""
        with self._lock:
            self._services.clear()
            self._factories.clear()

# Global default container instance
container = Container()
