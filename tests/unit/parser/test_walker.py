"""Unit tests for ASTWalker and Visitor Pattern implementation."""

from collections.abc import Iterator
from pathlib import Path

from karsasec.parser.ast import (
    ASTVisitor,
    ASTWalker,
    StopTraversal,
    TraversalStrategy,
    VisitorContext,
)
from karsasec.parser.ast_nodes import ASTNode, FileNode


def create_synthetic_ast() -> FileNode:
    """Helper to build a deterministic synthetic AST tree for unit testing."""
    root_node = FileNode(
        node_id="root_id",
        node_type="file",
        language="Python",
        file_path=Path("app.py"),
        children=["import_1", "import_2", "func_1"],
    )

    import_1 = ASTNode(node_id="import_1", parent_id="root_id", node_type="import_statement", language="Python")
    import_2 = ASTNode(node_id="import_2", parent_id="root_id", node_type="import_statement", language="Python")
    func_1 = ASTNode(node_id="func_1", parent_id="root_id", node_type="function_definition", language="Python", children=["call_1"])
    call_1 = ASTNode(node_id="call_1", parent_id="func_1", node_type="call_expression", language="Python")

    nodes_map = {
        "root_id": root_node,
        "import_1": import_1,
        "import_2": import_2,
        "func_1": func_1,
        "call_1": call_1,
    }
    root_node.nodes_map = nodes_map
    return root_node

def test_walker_streaming_iterator() -> None:
    root = create_synthetic_ast()

    walker = ASTWalker()
    stream = walker.walk(root)
    assert isinstance(stream, Iterator)

    nodes = list(stream)
    assert len(nodes) == 5
    assert nodes[0].node_type == "file"

def test_walker_dfs_and_bfs_strategy() -> None:
    root = create_synthetic_ast()
    walker = ASTWalker()

    dfs_nodes = list(walker.walk(root, strategy=TraversalStrategy.DFS))
    bfs_nodes = list(walker.walk(root, strategy=TraversalStrategy.BFS))

    assert len(dfs_nodes) == 5
    assert len(bfs_nodes) == 5

    # BFS order: root -> import_1 -> import_2 -> func_1 -> call_1
    bfs_types = [n.node_type for n in bfs_nodes]
    assert bfs_types == ["file", "import_statement", "import_statement", "function_definition", "call_expression"]

    # DFS order: root -> import_1 -> import_2 -> func_1 -> call_1
    dfs_types = [n.node_type for n in dfs_nodes]
    assert dfs_types == ["file", "import_statement", "import_statement", "function_definition", "call_expression"]

def test_stateless_visitor_and_context() -> None:
    root = create_synthetic_ast()

    class ImportCounterVisitor(ASTVisitor):
        def default_visit(self, node: ASTNode, context: VisitorContext) -> None:
            if "import" in node.node_type:
                count = context.user_state.get("imports", 0)
                context.user_state["imports"] = count + 1

    visitor = ImportCounterVisitor()
    context = VisitorContext(file_node=root)

    walker = ASTWalker()
    walker.walk_with_visitor(root, visitor, context=context)

    assert context.user_state.get("imports") == 2

def test_early_cancellation_stop_traversal() -> None:
    root = create_synthetic_ast()
    visited_count = 0

    class EarlyStopVisitor(ASTVisitor):
        def default_visit(self, node: ASTNode, context: VisitorContext) -> None:
            nonlocal visited_count
            visited_count += 1
            if visited_count >= 3:
                raise StopTraversal()

    walker = ASTWalker()
    walker.walk_with_visitor(root, EarlyStopVisitor())

    # Traversal should halt at exactly 3 nodes
    assert visited_count == 3
