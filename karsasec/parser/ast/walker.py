"""ASTWalker streaming iterator implementation operating directly on FileNode trees."""

from collections import deque
from typing import Iterator, Optional, Set, Type
from karsasec.parser.ast.context import VisitorContext
from karsasec.parser.ast.strategy import StopTraversal, TraversalStrategy
from karsasec.parser.ast.visitor import ASTVisitor
from karsasec.parser.ast_nodes import ASTNode, FileNode

class ASTWalker:
    """High-performance streaming AST Walker operating on FileNode root structures."""

    def walk(
        self,
        root: FileNode,
        strategy: TraversalStrategy = TraversalStrategy.DFS,
        node_types: Optional[Set[Type[ASTNode]]] = None,
    ) -> Iterator[ASTNode]:
        """Streams AST nodes from FileNode tree using DFS or BFS traversal and type-safe filtering."""
        if not root:
            return

        # If FileNode has nodes_map populated, use it for O(1) lookup
        nodes_map = root.nodes_map

        if strategy == TraversalStrategy.BFS:
            queue = deque([root.node_id if root.node_id else root])
            visited_ids = set()

            while queue:
                current_item = queue.popleft()
                current_node: Optional[ASTNode] = None

                if isinstance(current_item, str):
                    if current_item in visited_ids:
                        continue
                    visited_ids.add(current_item)
                    current_node = nodes_map.get(current_item)
                    if not current_node and current_item == root.node_id:
                        current_node = root
                elif isinstance(current_item, ASTNode):
                    current_node = current_item

                if not current_node:
                    continue

                if node_types is None or any(isinstance(current_node, t) for t in node_types):
                    yield current_node

                for child_id in current_node.children:
                    if child_id not in visited_ids:
                        queue.append(child_id)
        else:
            # Default DFS Strategy (Iterative stack)
            stack = [root.node_id if root.node_id else root]
            visited_ids = set()

            while stack:
                current_item = stack.pop()
                current_node = None

                if isinstance(current_item, str):
                    if current_item in visited_ids:
                        continue
                    visited_ids.add(current_item)
                    current_node = nodes_map.get(current_item)
                    if not current_node and current_item == root.node_id:
                        current_node = root
                elif isinstance(current_item, ASTNode):
                    current_node = current_item

                if not current_node:
                    continue

                if node_types is None or any(isinstance(current_node, t) for t in node_types):
                    yield current_node

                # Push children in reverse order so leftmost child is processed first in DFS
                for child_id in reversed(current_node.children):
                    if child_id not in visited_ids:
                        stack.append(child_id)

    def walk_with_visitor(
        self,
        root: FileNode,
        visitor: ASTVisitor,
        context: Optional[VisitorContext] = None,
        strategy: TraversalStrategy = TraversalStrategy.DFS,
        node_types: Optional[Set[Type[ASTNode]]] = None,
    ) -> None:
        """Walks FileNode tree and dispatches node visits to a stateless ASTVisitor.

        Catches StopTraversal exception for early termination.
        """
        ctx = context or VisitorContext(file_node=root, language=root.language, file_path=root.file_path)

        try:
            for node in self.walk(root, strategy=strategy, node_types=node_types):
                visitor.visit(node, ctx)
        except StopTraversal:
            # Early cancellation signal handled gracefully
            pass
