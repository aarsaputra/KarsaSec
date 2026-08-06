"""Data structures for Project Graph Nodes."""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class NodeKind(Enum):
    """Types of program elements represented as graph nodes."""
    MODULE = "MODULE"
    CLASS = "CLASS"
    FUNCTION = "FUNCTION"
    VARIABLE = "VARIABLE"
    EXPRESSION = "EXPRESSION"
    UNKNOWN = "UNKNOWN"

class Visibility(Enum):
    """Access visibility of functions and fields."""
    PUBLIC = "PUBLIC"
    PROTECTED = "PROTECTED"
    PRIVATE = "PRIVATE"

@dataclass(slots=True)
class GraphNode:
    """Represents a node in the project-wide Code Property Graph.

    Fields:
        uuid: Unique node identifier (e.g. hash or node_id).
        kind: NodeKind enum indicating structural type (MODULE, CLASS, FUNCTION, etc.).
        language: Programming language string.
        qualified_name: Fully qualified symbol path (e.g., 'auth.services.UserService.login').
        namespace: Enclosing namespace or module name.
        signature: Parameter signature for functions/methods.
        visibility: Access level (PUBLIC, PROTECTED, PRIVATE).
        file_path: Relative or absolute path to the source file.
        line: 1-indexed starting line.
        column: 0-indexed starting column.
        attributes: Additional metadata dict for extensions.
    """
    uuid: str
    kind: NodeKind = NodeKind.UNKNOWN
    language: str = ""
    qualified_name: str = ""
    namespace: str = ""
    signature: str = ""
    visibility: Visibility = Visibility.PUBLIC
    file_path: Path | None = None
    line: int = 1
    column: int = 0
    attributes: dict[str, str] = field(default_factory=dict)
