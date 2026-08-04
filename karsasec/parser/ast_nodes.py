"""AST Node Data Transfer Objects (DTOs) for unified multi-language AST representation."""

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Union

@dataclass(slots=True)
class Position:
    """Line and column offset position in source code."""
    line: int
    column: int

def generate_node_id(file_path: Union[str, Path], byte_start: int, byte_end: int, node_type: str) -> str:
    """Generates a deterministic SHA-1 node identifier for caching and CPG graph node linking."""
    normalized_path = str(file_path).replace("\\", "/")
    raw_key = f"{normalized_path}:{byte_start}:{byte_end}:{node_type}"
    return hashlib.sha1(raw_key.encode("utf-8")).hexdigest()[:16]

@dataclass(slots=True)
class ASTNode:
    """Base memory-efficient representation of an AST Node."""
    node_id: str = ""
    parent_id: Optional[str] = None
    node_type: str = "node"
    language: str = ""
    file_path: Optional[Path] = None
    byte_start: int = 0
    byte_end: int = 0
    start: Position = field(default_factory=lambda: Position(1, 0))
    end: Position = field(default_factory=lambda: Position(1, 0))
    children: List[str] = field(default_factory=list)  # Child node_ids to avoid circular references
    semantic_tags: List[str] = field(default_factory=list)  # Sprint 3 Rule Engine tags (Source, Sink, etc.)
    flow_tags: List[str] = field(default_factory=list)      # Sprint 4 CPG Control/Data Flow tags

    def get_text(self, source_bytes: bytes) -> str:
        """Lazily extracts and decodes text content from raw source code bytes."""
        if 0 <= self.byte_start <= self.byte_end <= len(source_bytes):
            return source_bytes[self.byte_start:self.byte_end].decode("utf-8", errors="ignore")
        return ""

@dataclass(slots=True)
class FileNode(ASTNode):
    """Top-level root AST node representing a whole source code file with O(1) node lookup map."""
    total_lines: int = 0
    encoding: str = "utf-8"
    nodes_map: Dict[str, ASTNode] = field(default_factory=dict)  # O(1) lookup table by node_id

    def __post_init__(self) -> None:
        self.node_type = "file"

@dataclass(slots=True)
class FunctionNode(ASTNode):
    """Representation of a function or method definition."""
    name: str = ""
    parameters: List[str] = field(default_factory=list)
    return_type: Optional[str] = None
    decorators: List[str] = field(default_factory=list)
    is_async: bool = False

@dataclass(slots=True)
class ClassNode(ASTNode):
    """Representation of a class definition."""
    name: str = ""
    base_classes: List[str] = field(default_factory=list)
    methods: List[str] = field(default_factory=list)  # FunctionNode node_ids

@dataclass(slots=True)
class ImportNode(ASTNode):
    """Representation of an import statement."""
    module_name: str = ""
    imported_symbols: List[str] = field(default_factory=list)
    alias: Optional[str] = None

@dataclass(slots=True)
class CallNode(ASTNode):
    """Representation of a function call (Sink analysis)."""
    function_name: str = ""
    arguments: List[str] = field(default_factory=list)
    kwarguments: Dict[str, str] = field(default_factory=dict)

@dataclass(slots=True)
class AssignmentNode(ASTNode):
    """Representation of a variable assignment (Source analysis)."""
    target: str = ""
    value_expression: str = ""
