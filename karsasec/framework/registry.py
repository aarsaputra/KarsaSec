"""Framework registry maintaining FrameworkDefinition entries decoupling registration from detection."""

from __future__ import annotations

import logging
from collections.abc import Sequence

from karsasec.framework.models import FrameworkDefinition, FrameworkType

logger = logging.getLogger("karsasec.framework.registry")


class FrameworkRegistry:
    """Registry maintaining static FrameworkDefinition objects without running detection logic."""

    def __init__(self) -> None:
        self._definitions: dict[str, FrameworkDefinition] = {}

    def register(self, definition: FrameworkDefinition) -> None:
        """Registers a FrameworkDefinition under its unique framework identifier or ID."""
        key = definition.id.upper()
        self._definitions[key] = definition
        logger.debug(f"Registered framework definition: {definition.name} ({key})")

    def unregister(self, framework_id: str) -> bool:
        """Removes a framework definition from the registry."""
        key = framework_id.upper()
        if key in self._definitions:
            del self._definitions[key]
            return True
        return False

    def lookup(self, framework_id: str | FrameworkType) -> FrameworkDefinition | None:
        """Retrieves a FrameworkDefinition by ID or FrameworkType."""
        key = framework_id.value.upper() if isinstance(framework_id, FrameworkType) else str(framework_id).upper()
        return self._definitions.get(key)

    def supported(self) -> list[str]:
        """Returns list of all supported registered framework IDs."""
        return sorted(list(self._definitions.keys()))

    def get_all(self) -> Sequence[FrameworkDefinition]:
        """Returns all registered FrameworkDefinition objects."""
        return list(self._definitions.values())

    def clear(self) -> None:
        """Clears all registered framework definitions."""
        self._definitions.clear()


# Global default registry instance
framework_registry = FrameworkRegistry()
