"""Dependency Injection Container for managing application components."""

from typing import Any, Callable, Dict, Type, TypeVar

T = TypeVar("T")

class Container:
    """Simple lightweight Dependency Injection (IoC) Container."""
    
    def __init__(self) -> None:
        self._services: Dict[Type[Any], Any] = {}
        self._factories: Dict[Type[Any], Callable[[], Any]] = {}
    
    def register_singleton(self, interface: Type[T], instance: T) -> None:
        """Registers a singleton instance for a given type interface."""
        self._services[interface] = instance
    
    def register_factory(self, interface: Type[T], factory: Callable[[], T]) -> None:
        """Registers a factory callable that creates a new instance on resolve."""
        self._factories[interface] = factory
    
    def resolve(self, interface: Type[T]) -> T:
        """Resolves a registered service or raises KeyError if unregistered."""
        if interface in self._services:
            return self._services[interface]  # type: ignore[no-any-return]
        
        if interface in self._factories:
            return self._factories[interface]()  # type: ignore[no-any-return]
            
        raise KeyError(f"Service '{interface.__name__}' is not registered in the Container.")
    
    def reset(self) -> None:
        """Resets all registered services."""
        self._services.clear()
        self._factories.clear()

# Global default container instance
container = Container()
