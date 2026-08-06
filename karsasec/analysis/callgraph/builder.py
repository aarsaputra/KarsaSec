"""CallGraphBuilder module for constructing interprocedural CallGraph models from AST IR."""


from karsasec.analysis.callgraph.models import CallEdge, CallGraph
from karsasec.analysis.callgraph.models import CallNode as GraphCallNode
from karsasec.parser.ast_nodes import CallNode as ASTCallNode
from karsasec.parser.ast_nodes import FileNode, FunctionNode


class CallGraphBuilder:
    """Constructs a multi-file CallGraph from AST FileNode trees."""

    def __init__(self) -> None:
        pass

    def build_from_file_nodes(self, file_nodes: list[FileNode], source_bytes_map: dict[str, bytes] | None = None) -> CallGraph:
        """Builds a unified CallGraph across one or multiple FileNode instances."""
        graph = CallGraph()
        source_bytes_map = source_bytes_map or {}

        # Step 1: Collect all function declarations (GraphCallNode)
        for fn in file_nodes:
            self._extract_declarations(fn, graph)

        # Step 2: Extract function call sites (CallEdge)
        for fn in file_nodes:
            source_bytes = source_bytes_map.get(str(fn.file_path), b"")
            self._extract_call_sites(fn, graph, source_bytes)

        return graph

    def _extract_declarations(self, file_node: FileNode, graph: CallGraph) -> None:
        """Traverses AST nodes to discover function and method declarations."""
        file_path_str = str(file_node.file_path) if file_node.file_path else "unknown"

        for node_id, node in file_node.nodes_map.items():
            if isinstance(node, FunctionNode) or node.node_type in ["function_definition", "function_declaration", "method_declaration", "def", "func_decl"]:
                func_name = getattr(node, "name", "") or "anonymous"
                parameters = getattr(node, "parameters", [])

                node_id_str = f"{file_path_str}::{func_name}::{node.start.line}"
                call_node = GraphCallNode(
                    id=node_id_str,
                    name=func_name,
                    language=node.language or file_node.language,
                    file_path=file_path_str,
                    line_number=node.start.line,
                    parameters=parameters if isinstance(parameters, list) else [],
                )
                graph.add_node(call_node)

    def _extract_call_sites(self, file_node: FileNode, graph: CallGraph, source_bytes: bytes) -> None:
        """Traverses AST nodes inside function bodies to record call edges."""
        file_path_str = str(file_node.file_path) if file_node.file_path else "unknown"

        # Find function scope for call nodes
        for node_id, node in file_node.nodes_map.items():
            if isinstance(node, ASTCallNode) or node.node_type in ["call", "call_expression"]:
                callee_name = getattr(node, "callee_name", "") or getattr(node, "function_name", "") or ""
                if not callee_name and source_bytes:
                    callee_name = node.get_text(source_bytes)

                if callee_name:
                    # Resolve active caller function scope
                    caller_id = f"{file_path_str}::main::{node.start.line}"
                    curr_parent_id = node.parent_id
                    while curr_parent_id and curr_parent_id in file_node.nodes_map:
                        parent_node = file_node.nodes_map[curr_parent_id]
                        if isinstance(parent_node, FunctionNode) or parent_node.node_type in ["function_definition", "function_declaration", "def", "func_decl"]:
                            p_name = getattr(parent_node, "name", "anonymous")
                            caller_id = f"{file_path_str}::{p_name}::{parent_node.start.line}"
                            break
                        curr_parent_id = parent_node.parent_id

                    resolved_nodes = graph.get_node_by_name(callee_name)
                    target_id = resolved_nodes[0].id if resolved_nodes else None

                    edge = CallEdge(
                        caller_id=caller_id,
                        callee_name=callee_name,
                        line_number=node.start.line,
                        arguments=getattr(node, "arguments", []),
                        target_node_id=target_id,
                    )
                    graph.add_edge(edge)
