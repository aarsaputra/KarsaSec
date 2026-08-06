"""CFGBuilder module translating Universal IR functions to Control Flow Graphs."""

from __future__ import annotations

from karsasec.analysis.cfg.models import (
    CFG,
    CFGEdgeType,
    CFGNode,
    CFGNodeType,
    EntryNode,
    ExitNode,
)
from karsasec.ir.nodes import IRAssignment, IRCall, IRFunction, IRIf, IRLoop, IRReturn, IRStatement


class CFGBuilder:
    """Translates Universal IRFunction objects into deterministic Control Flow Graphs (CFG)."""

    def build_cfg_for_functions(self, ir_functions: list[IRFunction]) -> dict[str, CFG]:
        """Translates a list of IRFunction objects into a dictionary of function name -> CFG."""
        cfgs: dict[str, CFG] = {}
        for ir_func in ir_functions:
            cfg = self.build_cfg(ir_func)
            cfgs[ir_func.name] = cfg
        return cfgs

    def build_cfg(self, ir_func: IRFunction) -> CFG:
        """Constructs a CFG for a single IRFunction."""
        cfg = CFG(function_name=ir_func.name, file_path=ir_func.file_path)

        # Step 1: Create ENTRY and EXIT nodes
        entry = EntryNode(cfg_id=ir_func.id, line_number=ir_func.line_number)
        exit_node = ExitNode(cfg_id=ir_func.id, line_number=ir_func.line_number)

        cfg.add_node(entry)
        cfg.add_node(exit_node)

        if not ir_func.body_statements:
            # Empty function body -> direct ENTRY -> EXIT edge
            cfg.add_edge(entry.id, exit_node.id, CFGEdgeType.NORMAL)
            return cfg

        # Step 2: Build Control Flow Graph nodes and edges for body statements
        last_node_id = self._build_statements_cfg(ir_func.body_statements, entry.id, exit_node.id, cfg, ir_func)

        # Step 3: Link remaining tail node to EXIT node if not already connected
        if last_node_id and last_node_id != exit_node.id:
            if last_node_id not in [e.source_id for e in cfg.edges if e.target_id == exit_node.id]:
                cfg.add_edge(last_node_id, exit_node.id, CFGEdgeType.NORMAL)

        return cfg

    def _build_statements_cfg(
        self,
        statements: list[IRStatement],
        current_head_id: str,
        exit_node_id: str,
        cfg: CFG,
        ir_func: IRFunction,
    ) -> str:
        """Processes a list of IRStatements, creating nodes and linking control flow edges."""
        prev_id = current_head_id
        idx = 0

        while idx < len(statements):
            stmt = statements[idx]

            # If it's a basic assignment or call, group contiguous basic statements
            if isinstance(stmt, (IRAssignment, IRCall)):
                block_stmts: list[IRStatement] = [stmt]
                idx += 1
                while idx < len(statements) and isinstance(statements[idx], (IRAssignment, IRCall)):
                    block_stmts.append(statements[idx])
                    idx += 1

                stmt_id = f"{ir_func.id}::stmt::{stmt.line_number}::{idx}"
                stmt_node = CFGNode(
                    id=stmt_id,
                    node_type=CFGNodeType.STATEMENT,
                    line_number=stmt.line_number,
                    statements=block_stmts,
                    label=f"Statement Block ({len(block_stmts)} instrs)",
                )
                cfg.add_node(stmt_node)
                cfg.add_edge(prev_id, stmt_id, CFGEdgeType.NORMAL)
                prev_id = stmt_id

            elif isinstance(stmt, IRIf):
                idx += 1
                # Create Condition Node
                if_id = f"{ir_func.id}::if::{stmt.line_number}"
                cond_node = CFGNode(
                    id=if_id,
                    node_type=CFGNodeType.CONDITION,
                    line_number=stmt.line_number,
                    label=f"If ({stmt.condition_expr})",
                )
                cfg.add_node(cond_node)
                cfg.add_edge(prev_id, if_id, CFGEdgeType.NORMAL)

                # Process True Branch
                true_head_id = f"{if_id}::then"
                true_node = CFGNode(
                    id=true_head_id,
                    node_type=CFGNodeType.STATEMENT,
                    line_number=stmt.line_number,
                    statements=stmt.then_statements,
                    label="Then Branch",
                )
                cfg.add_node(true_node)
                cfg.add_edge(if_id, true_head_id, CFGEdgeType.TRUE_BRANCH, condition_text="True")
                true_tail_id = true_head_id

                # Process Else Branch
                false_head_id = f"{if_id}::else"
                false_node = CFGNode(
                    id=false_head_id,
                    node_type=CFGNodeType.STATEMENT,
                    line_number=stmt.line_number,
                    statements=stmt.else_statements,
                    label="Else Branch",
                )
                cfg.add_node(false_node)
                cfg.add_edge(if_id, false_head_id, CFGEdgeType.FALSE_BRANCH, condition_text="False")
                false_tail_id = false_head_id

                # Merge Node
                merge_id = f"{if_id}::merge"
                merge_node = CFGNode(
                    id=merge_id,
                    node_type=CFGNodeType.STATEMENT,
                    line_number=stmt.line_number,
                    label="Merge",
                )
                cfg.add_node(merge_node)
                cfg.add_edge(true_tail_id, merge_id, CFGEdgeType.NORMAL)
                cfg.add_edge(false_tail_id, merge_id, CFGEdgeType.NORMAL)

                prev_id = merge_id

            elif isinstance(stmt, IRLoop):
                idx += 1
                loop_id = f"{ir_func.id}::loop::{stmt.line_number}"
                loop_cond_node = CFGNode(
                    id=loop_id,
                    node_type=CFGNodeType.LOOP,
                    line_number=stmt.line_number,
                    label=f"Loop Header ({stmt.loop_type})",
                )
                cfg.add_node(loop_cond_node)
                cfg.add_edge(prev_id, loop_id, CFGEdgeType.NORMAL)

                body_head_id = f"{loop_id}::body"
                body_node = CFGNode(
                    id=body_head_id,
                    node_type=CFGNodeType.STATEMENT,
                    line_number=stmt.line_number,
                    statements=stmt.body_statements,
                    label="Loop Body",
                )
                cfg.add_node(body_node)
                cfg.add_edge(loop_id, body_head_id, CFGEdgeType.TRUE_BRANCH)
                cfg.add_edge(body_head_id, loop_id, CFGEdgeType.LOOP_BACK)

                loop_exit_id = f"{loop_id}::exit"
                loop_exit_node = CFGNode(
                    id=loop_exit_id,
                    node_type=CFGNodeType.STATEMENT,
                    line_number=stmt.line_number,
                    label="Loop Exit",
                )
                cfg.add_node(loop_exit_node)
                cfg.add_edge(loop_id, loop_exit_id, CFGEdgeType.FALSE_BRANCH)

                prev_id = loop_exit_id

            elif isinstance(stmt, IRReturn):
                idx += 1
                ret_id = f"{ir_func.id}::return::{stmt.line_number}"
                ret_node = CFGNode(
                    id=ret_id,
                    node_type=CFGNodeType.RETURN,
                    line_number=stmt.line_number,
                    label=f"Return ({stmt.value_expression})",
                )
                cfg.add_node(ret_node)
                cfg.add_edge(prev_id, ret_id, CFGEdgeType.NORMAL)
                cfg.add_edge(ret_id, exit_node_id, CFGEdgeType.RETURN_EDGE)
                prev_id = ret_id

            else:
                idx += 1

        return prev_id
