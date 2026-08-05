"""VisitorContext model encapsulating AST traversal metadata and visitor state."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional
from karsasec.core.plugin import SymbolTable
from karsasec.parser.ast_nodes import FileNode

@dataclass(slots=True)
class VisitorContext:
    """Encapsulates context, metadata, and user accumulation state during AST traversal."""
    file_node: FileNode
    symbol_table: Optional[SymbolTable] = None
    language: str = ""
    file_path: Optional[Path] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    user_state: Dict[str, Any] = field(default_factory=dict)
    semantic_graph: Optional[Any] = None

