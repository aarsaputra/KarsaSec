"""Data structures for Project Graph Edges."""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, Optional

class EdgeType(Enum):
    """Structural and behavioral relationship types between graph nodes."""
    CALLS = "CALLS"
    IMPORTS = "IMPORTS"
    DEFINES = "DEFINES"
    INHERITS = "INHERITS"
    DATAFLOW = "DATAFLOW"

class ResolutionMechanism(Enum):
    """Method used by the resolver engine to establish an edge."""
    AST_NATIVE = "AST_NATIVE"
    ALIAS_TRACKER = "ALIAS_TRACKER"
    REGEX_FALLBACK = "REGEX_FALLBACK"
    DYNAMIC = "DYNAMIC"
    UNRESOLVED = "UNRESOLVED"

@dataclass(slots=True)
class GraphEdge:
    """Represents a directional relationship between two nodes in the Project Graph.

    Fields:
        caller_id: Node UUID of the source/caller node.
        callee_id: Node UUID of the target/callee node.
        edge_type: Relationship type (CALLS, IMPORTS, DEFINES, INHERITS, DATAFLOW).
        confidence: Floating point confidence score (0.0 to 1.0).
        resolved_symbol: Fully qualified symbol string resolved for this edge.
        resolved_by: Mechanism used to resolve this relationship.
        call_site_id: Node ID of the specific AST call site expression.
        attributes: Additional metadata dictionary.
    """
    caller_id: str
    callee_id: str
    edge_type: EdgeType = EdgeType.CALLS
    confidence: float = 1.0
    resolved_symbol: str = ""
    resolved_by: ResolutionMechanism = ResolutionMechanism.AST_NATIVE
    call_site_id: Optional[str] = None
    attributes: Dict[str, str] = field(default_factory=dict)
