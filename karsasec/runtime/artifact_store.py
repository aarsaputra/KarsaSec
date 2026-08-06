"""Centralized Analysis Artifact Store decoupling analysis passes via immutable artifact exchanges."""

from typing import Any, TypeVar

T = TypeVar("T")


class ArtifactStore:
    """Centralized repository storing immutable intermediate analysis artifacts (AST, HIR, MIR, LIR, CFG, etc.)."""

    def __init__(self) -> None:
        self._artifacts: dict[str, Any] = {}

    def put(self, key: str, artifact: Any) -> None:
        """Stores an artifact under a unique key."""
        self._artifacts[key] = artifact

    def get(self, key: str, expected_type: type[T] | None = None) -> T | None:
        """Retrieves an artifact by key, optionally asserting expected type."""
        val = self._artifacts.get(key)
        if val is not None and expected_type is not None and not isinstance(val, expected_type):
            raise TypeError(f"Artifact under key '{key}' is type {type(val)}, expected {expected_type}")
        return val

    def has(self, key: str) -> bool:
        return key in self._artifacts

    def clear(self) -> None:
        self._artifacts.clear()


artifact_store = ArtifactStore()
