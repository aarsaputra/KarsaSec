"""Semantic registry providing multi-index lookup and management for semantic entities."""

from __future__ import annotations

import logging
from typing import Any

from karsasec.framework.intermediate import (
    ControllerDefinition,
    HandlerDefinition,
    RouteDefinition,
)

logger = logging.getLogger("karsasec.framework.semantic_registry")


class SemanticRegistry:
    """Registry maintaining semantic items, routes, handlers, controllers, files, and CPG links."""

    def __init__(self) -> None:
        self._items: dict[str, Any] = {}
        self._routes: dict[str, RouteDefinition] = {}  # path -> RouteDefinition
        self._handlers: dict[str, HandlerDefinition] = {}  # handler_name -> HandlerDefinition
        self._controllers: dict[str, ControllerDefinition] = {}  # controller_name -> ControllerDefinition
        self._file_map: dict[str, list[Any]] = {}  # file_path -> items
        self._cpg_map: dict[str, Any] = {}  # cpg_id -> item

    def lookup(self, item_id: str) -> Any | None:
        """Retrieves registered semantic item by unique ID or key."""
        return self._items.get(item_id)

    def lookup_route(self, path: str) -> RouteDefinition | None:
        """Retrieves RouteDefinition by endpoint path."""
        return self._routes.get(path)

    def lookup_handler(self, handler_name: str) -> HandlerDefinition | None:
        """Retrieves HandlerDefinition by handler name."""
        return self._handlers.get(handler_name)

    def lookup_controller(self, controller_name: str) -> ControllerDefinition | None:
        """Retrieves ControllerDefinition by controller name."""
        return self._controllers.get(controller_name)

    def lookup_file(self, file_path: str) -> list[Any]:
        """Retrieves list of registered items associated with a file path."""
        return self._file_map.get(file_path, [])

    def lookup_cpg(self, cpg_id: str) -> Any | None:
        """Retrieves registered item associated with a CPG Node ID."""
        return self._cpg_map.get(cpg_id)

    def add(self, item_id: str, item: Any) -> None:
        """Registers a semantic item under a key and updates indices."""
        self._items[item_id] = item

        if isinstance(item, RouteDefinition):
            self._routes[item.path] = item
        elif isinstance(item, HandlerDefinition):
            self._handlers[item.name] = item
        elif isinstance(item, ControllerDefinition):
            self._controllers[item.name] = item

        # File index
        origin = getattr(item, "origin", None)
        if origin and hasattr(origin, "location_info") and origin.location_info.file_path:
            fp = origin.location_info.file_path
            self._file_map.setdefault(fp, []).append(item)

        # CPG index
        cpg_ref = getattr(item, "cpg_ref", None)
        if cpg_ref:
            self._cpg_map[cpg_ref] = item

    def remove(self, item_id: str) -> bool:
        """Removes a registered item and updates indices."""
        item = self._items.pop(item_id, None)
        if item is None:
            return False

        if isinstance(item, RouteDefinition):
            self._routes.pop(item.path, None)
        elif isinstance(item, HandlerDefinition):
            self._handlers.pop(item.name, None)
        elif isinstance(item, ControllerDefinition):
            self._controllers.pop(item.name, None)

        cpg_ref = getattr(item, "cpg_ref", None)
        if cpg_ref:
            self._cpg_map.pop(cpg_ref, None)
        return True

    def replace(self, item_id: str, new_item: Any) -> None:
        """Replaces an existing registered item."""
        self.remove(item_id)
        self.add(item_id, new_item)

    def merge(self, other: SemanticRegistry) -> None:
        """Merges items and indices from another SemanticRegistry instance."""
        for item_id, item in other._items.items():
            self.add(item_id, item)

    def clear(self) -> None:
        """Clears all registry state."""
        self._items.clear()
        self._routes.clear()
        self._handlers.clear()
        self._controllers.clear()
        self._file_map.clear()
        self._cpg_map.clear()


# Global default semantic registry instance
semantic_registry = SemanticRegistry()
