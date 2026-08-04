"""ScanContext model encapsulating target file node, mandatory source bytes, project root, and symbol table."""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from karsasec.core.plugin import SymbolTable
from karsasec.parser.ast_nodes import FileNode

@dataclass(slots=True)
class ScanContext:
    """Encapsulates scan parameters for file-level and repository-wide static analysis execution."""
    file_node: FileNode
    source_bytes: bytes
    project_root: Optional[Path] = None
    symbol_table: Optional[SymbolTable] = None
    language: str = ""
    file_path: Optional[Path] = None

    def __post_init__(self) -> None:
        if not self.language and self.file_node:
            self.language = self.file_node.language
        if not self.file_path and self.file_node:
            self.file_path = self.file_node.file_path
