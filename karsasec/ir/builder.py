"""IRBuilder module for converting FileNode AST trees to Universal IR nodes."""

from __future__ import annotations

from typing import Any

from karsasec.ir.nodes import (
    IRAssignment,
    IRCall,
    IRFunction,
    IRIf,
    IRLoop,
    IRStatement,
)
from karsasec.parser.ast_nodes import (
    AssignmentNode,
    ASTNode,
    FileNode,
    FunctionNode,
)
from karsasec.parser.ast_nodes import (
    CallNode as ASTCallNode,
)


class IRBuilder:
    """Translates multi-language FileNode AST structures into Universal IR trees."""

    def build_from_file_nodes(self, file_nodes: list[FileNode], source_bytes_map: dict[str, bytes] | None = None) -> list[IRFunction]:
        """Translates FileNode trees into universal IRFunction list."""
        functions: list[IRFunction] = []
        source_bytes_map = source_bytes_map or {}

        for fn in file_nodes:
            source_bytes = source_bytes_map.get(str(fn.file_path), b"")
            self._convert_file_node(fn, functions, source_bytes)

        return functions

    def _convert_file_node(self, file_node: FileNode, functions: list[IRFunction], source_bytes: bytes) -> None:
        file_path_str = str(file_node.file_path) if file_node.file_path else "unknown"

        for node_id, node in file_node.nodes_map.items():
            if isinstance(node, FunctionNode) or node.node_type in ["function_definition", "function_declaration", "def", "func_decl"]:
                func_name = getattr(node, "name", "") or "anonymous"
                params = getattr(node, "parameters", [])

                ir_func = IRFunction(
                    id=f"{file_path_str}::{func_name}::{node.start.line}",
                    line_number=node.start.line,
                    file_path=file_path_str,
                    language=node.language or file_node.language,
                    name=func_name,
                    parameters=params if isinstance(params, list) else [],
                )

                # Extract statements inside this function body
                for child_id in file_node.nodes_map:
                    child = file_node.nodes_map[child_id]
                    if child.parent_id == node.node_id:
                        stmt = self._convert_statement(child, file_node, source_bytes)
                        if stmt:
                            ir_func.body_statements.append(stmt)

                functions.append(ir_func)

    def _convert_statement(self, node: ASTNode, file_node: FileNode, source_bytes: bytes) -> IRStatement | None:
        file_path_str = str(file_node.file_path) if file_node.file_path else "unknown"
        line_no = node.start.line
        lang = node.language or file_node.language

        if isinstance(node, AssignmentNode) or node.node_type in ["assignment", "assignment_expression"]:
            target = getattr(node, "target", "")
            val_expr = getattr(node, "value_expression", "") or getattr(node, "value", "")
            return IRAssignment(
                id=f"{file_path_str}::assign::{line_no}",
                line_number=line_no,
                file_path=file_path_str,
                language=lang,
                target=target,
                value_expression=val_expr,
            )

        elif isinstance(node, ASTCallNode) or node.node_type in ["call", "call_expression"]:
            callee = getattr(node, "function_name", "") or getattr(node, "callee_name", "")
            args = getattr(node, "arguments", [])
            return IRCall(
                id=f"{file_path_str}::call::{line_no}",
                line_number=line_no,
                file_path=file_path_str,
                language=lang,
                callee_name=callee,
                arguments=args if isinstance(args, list) else [],
            )

        elif "if" in node.node_type.lower():
            cond = getattr(node, "condition", "") or getattr(node, "condition_expr", "")
            return IRIf(
                id=f"{file_path_str}::if::{line_no}",
                line_number=line_no,
                file_path=file_path_str,
                language=lang,
                condition_expr=cond,
            )

        elif any(k in node.node_type.lower() for k in ["loop", "for", "while"]):
            loop_type = "WHILE" if "while" in node.node_type.lower() else "FOR"
            return IRLoop(
                id=f"{file_path_str}::loop::{line_no}",
                line_number=line_no,
                file_path=file_path_str,
                language=lang,
                loop_type=loop_type,
            )

        return None

    def build_call(self, node_id: str, callee_name: str, line: int = 1) -> IRCall:
        return IRCall(
            id=node_id,
            line_number=line,
            file_path="",
            language="",
            callee_name=callee_name,
        )

    def build_assign(self, node_id: str, target: str, value: Any, line: int = 1) -> IRAssignment:
        return IRAssignment(
            id=node_id,
            line_number=line,
            file_path="",
            language="",
            target=target,
            value_expression=value,
        )


ir_builder = IRBuilder()
