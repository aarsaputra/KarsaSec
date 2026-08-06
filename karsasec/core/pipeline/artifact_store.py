"""ArtifactStore module for immutable registry of compiler artifacts."""

from __future__ import annotations

from typing import Any


class ArtifactStore:
    """Immutable registry storing generated analysis artifacts (AST, SymbolGraph, CallGraph, CFG, CPG)."""

    def __init__(self) -> None:
        self._artifacts: dict[str, Any] = {}

    def store(self, artifact_name: str, data: Any) -> None:
        """Stores an artifact data object under the given name."""
        self._artifacts[artifact_name] = data

    def get(self, artifact_name: str) -> Any | None:
        """Retrieves a stored artifact by name."""
        return self._artifacts.get(artifact_name)

    def has(self, artifact_name: str) -> bool:
        """Checks if an artifact exists in the store."""
        return artifact_name in self._artifacts

    def keys(self) -> list[str]:
        """Returns list of all stored artifact names."""
        return list(self._artifacts.keys())

    def to_dict(self) -> dict[str, Any]:
        """Serializes artifact metadata overview to dictionary."""
        overview: dict[str, Any] = {}
        for k, v in self._artifacts.items():
            if hasattr(v, "to_dict"):
                overview[k] = v.to_dict()
            else:
                overview[k] = str(type(v))
        return overview
