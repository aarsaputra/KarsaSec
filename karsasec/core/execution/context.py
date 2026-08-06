"""ScanContext model encapsulating target file node, mandatory source bytes, project root, and symbol table."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from karsasec.core.plugin import SymbolTable
from karsasec.parser.ast_nodes import FileNode

if TYPE_CHECKING:
    pass

@dataclass(slots=True)
class ScanContext:
    """Encapsulates scan parameters for file-level and repository-wide static analysis execution.

    Fields:
        file_node:    Root FileNode for the file being analyzed.
        source_bytes: Raw source bytes for accurate text extraction.
        project_root: Optional project root path for cross-file context.
        symbol_table: Language-level symbol extract.
        language:     Language identifier string.
        file_path:    Absolute path of the target file.
        call_graph:   Optional pre-built cross-file CallGraph for inter-procedural rule matching.
                      When provided, SymbolPredicate gains cross-file callee resolution.
    """
    file_node: FileNode
    source_bytes: bytes
    project_root: Path | None = None
    symbol_table: SymbolTable | None = None
    language: str = ""
    file_path: Path | None = None
    call_graph: object | None = None  # CallGraph — typed as object to avoid circular imports at runtime
    rag_context: tuple[dict[str, Any], ...] = ()

    def __post_init__(self) -> None:
        if not self.language and self.file_node:
            self.language = self.file_node.language
        if not self.file_path and self.file_node:
            self.file_path = self.file_node.file_path
