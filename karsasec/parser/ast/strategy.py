"""TraversalStrategy enum and StopTraversal exception signal for AST Walker."""

from enum import Enum

class TraversalStrategy(str, Enum):
    """AST Traversal strategy options."""
    DFS = "DFS"  # Depth-First Search (Default)
    BFS = "BFS"  # Breadth-First Search

class StopTraversal(Exception):
    """Exception signal raised by visitors to immediately halt AST traversal."""
    pass
