"""PassContext module for encapsulating pipeline state and artifact store access."""

from __future__ import annotations

from typing import Any

from karsasec.core.pipeline.artifact_store import ArtifactStore
from karsasec.parser.ast_nodes import FileNode


class PassContext:
    """Execution context passed through each AnalysisPass in the compiler pipeline."""

    def __init__(
        self, file_nodes: list[FileNode] | None = None, source_bytes_map: dict[str, bytes] | None = None
    ) -> None:
        self.file_nodes: list[FileNode] = file_nodes or []
        self.source_bytes_map: dict[str, bytes] = source_bytes_map or {}
        self.artifact_store: ArtifactStore = ArtifactStore()
        self.metadata: dict[str, Any] = {}
