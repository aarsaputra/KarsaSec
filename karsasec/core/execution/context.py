"""ScanContext model encapsulating target file node, mandatory source bytes, project root, and symbol table."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Optional
from karsasec.core.plugin import SymbolTable
from karsasec.parser.ast_nodes import FileNode

if TYPE_CHECKING:
    from karsasec.graph.graph import CallGraph

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
    project_root: Optional[Path] = None
    symbol_table: Optional[SymbolTable] = None
    language: str = ""
    file_path: Optional[Path] = None
    call_graph: Optional[object] = None  # CallGraph — typed as object to avoid circular imports at runtime

    def __post_init__(self) -> None:
        if not self.language and self.file_node:
            self.language = self.file_node.language
        if not self.file_path and self.file_node:
            self.file_path = self.file_node.file_path
