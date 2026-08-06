"""SymbolResolver module for constructing SymbolGraph DTOs across AST FileNode trees."""

from __future__ import annotations

from karsasec.analysis.symbol.models import Symbol, SymbolGraph
from karsasec.parser.ast_nodes import (
    AssignmentNode,
    ClassNode,
    FileNode,
    FunctionNode,
    ImportNode,
)


class SymbolResolver:
    """Performs scope resolution, import binding, and qualified symbol tracking across AST trees."""

    def __init__(self) -> None:
        pass

    def build_symbol_graph(self, file_nodes: list[FileNode], source_bytes_map: dict[str, bytes] | None = None) -> SymbolGraph:
        """Builds a unified SymbolGraph across one or multiple FileNode instances."""
        graph = SymbolGraph()
        source_bytes_map = source_bytes_map or {}

        for fn in file_nodes:
            source_bytes = source_bytes_map.get(str(fn.file_path), b"")
            self._resolve_file_symbols(fn, graph, source_bytes)

        return graph

    def _resolve_file_symbols(self, file_node: FileNode, graph: SymbolGraph, source_bytes: bytes) -> None:
        file_path_str = str(file_node.file_path) if file_node.file_path else "unknown"

        # Step 1: Collect imports and alias declarations
        for node_id, node in file_node.nodes_map.items():
            if isinstance(node, ImportNode) or node.node_type in ["import", "import_declaration", "use_declaration"]:
                module_name = getattr(node, "module_name", "") or ""
                alias = getattr(node, "alias", None) or module_name
                if module_name:
                    graph.add_import(alias, module_name)
                    if module_name != alias:
                        graph.add_import(module_name, module_name)

        # Step 2: Collect symbol declarations and variable assignments
        for node_id, node in file_node.nodes_map.items():
            line_no = node.start.line

            # Function symbols
            if isinstance(node, FunctionNode) or node.node_type in ["function_definition", "function_declaration", "def", "func_decl"]:
                func_name = getattr(node, "name", "") or "anonymous"
                symbol_id = f"{file_path_str}::{func_name}::{line_no}"
                sym = Symbol(
                    id=symbol_id,
                    name=func_name,
                    qualified_name=f"{file_path_str}.{func_name}",
                    scope_name="global",
                    symbol_type="FUNCTION",
                    file_path=file_path_str,
                    line_number=line_no,
                )
                graph.add_symbol(sym)
                graph.bind_identifier(node.node_id, symbol_id)

            # Class symbols
            elif isinstance(node, ClassNode) or node.node_type in ["class_definition", "class_declaration", "struct"]:
                class_name = getattr(node, "name", "") or "anonymous"
                symbol_id = f"{file_path_str}::{class_name}::{line_no}"
                sym = Symbol(
                    id=symbol_id,
                    name=class_name,
                    qualified_name=f"{file_path_str}.{class_name}",
                    scope_name="global",
                    symbol_type="CLASS",
                    file_path=file_path_str,
                    line_number=line_no,
                )
                graph.add_symbol(sym)
                graph.bind_identifier(node.node_id, symbol_id)

            # Variable assignments (e.g., db = sqlite3.connect())
            elif isinstance(node, AssignmentNode) or node.node_type in ["assignment", "assignment_expression", "var_decl"]:
                var_name = getattr(node, "target", "") or getattr(node, "variable_name", "") or ""
                if not var_name and source_bytes:
                    var_name = node.get_text(source_bytes)

                if var_name:
                    sym_type = "VARIABLE"
                    value_text = getattr(node, "value_expression", "") or getattr(node, "value", "") or ""

                    # Check if assigned value references an imported module/constructor
                    target_qual = var_name
                    for imported_alias, full_path in graph.to_dict()["imports"].items():
                        if imported_alias in value_text or full_path in value_text:
                            target_qual = f"{full_path}.{var_name}"
                            sym_type = "INSTANCE"
                            break

                    symbol_id = f"{file_path_str}::{var_name}::{line_no}"
                    sym = Symbol(
                        id=symbol_id,
                        name=var_name,
                        qualified_name=target_qual,
                        scope_name="file_scope",
                        symbol_type=sym_type,
                        file_path=file_path_str,
                        line_number=line_no,
                    )
                    graph.add_symbol(sym)
                    graph.bind_identifier(node.node_id, symbol_id)
                    graph.bind_identifier(var_name, symbol_id)
