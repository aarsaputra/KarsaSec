"""VisitorContext model encapsulating AST traversal metadata and visitor state."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from karsasec.core.plugin import SymbolTable
from karsasec.parser.ast_nodes import FileNode

if TYPE_CHECKING:
    pass


@dataclass(slots=True)
class VisitorContext:
    """Encapsulates context, metadata, and user accumulation state during AST traversal.

    Fields:
        file_node:      Root FileNode for the file being analyzed.
        symbol_table:   Language-level symbol extract (functions, imports, globals).
        language:       Language identifier string (e.g., 'Python', 'Go').
        file_path:      Absolute path of the current file being analyzed.
        metadata:       Arbitrary metadata dict for plugin state.
        user_state:     Accumulator dict for visitor-specific state.
        semantic_graph: Per-file SemanticGraph with scope/alias resolution.
        call_graph:     Optional cross-file CallGraph for inter-procedural analysis.
                        Populated by the executor when project-wide analysis is active.
    """

    file_node: FileNode
    symbol_table: SymbolTable | None = None
    language: str = ""
    file_path: Path | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    user_state: dict[str, Any] = field(default_factory=dict)
    semantic_graph: Any | None = None
    call_graph: Any | None = None  # CallGraph — typed as Any to avoid circular imports at runtime
    rag_context: tuple[dict[str, Any], ...] = field(default_factory=tuple)
