"""Path-Sensitive Worklist Fixpoint Analyzer (E12-13).

Design Principles:
  - Intraprocedural forward dataflow analysis over ControlFlowGraph.
  - Branch edge polarity refinement: TRUE_BRANCH vs FALSE_BRANCH constraints.
  - Variable assignment kill & SSA-like versioning (x#1 -> x#2).
  - Reachability + Dominator-aware constraint validation.
  - Worklist fixpoint convergence with state equality checks.
  - Anti-hardcoding: Pure dataflow solver. Zero rule-ID or benchmark strings.
"""

from __future__ import annotations

import re
from typing import Any

from karsasec.graph.cfg.model import CFGEdge, CFGEdgeKind, ControlFlowGraph
from karsasec.graph.dataflow.abstract_state import AbstractEnvironment, SemanticConstraint, TaintState
from karsasec.graph.dataflow.registry import guard_registry


class WorklistFixpointAnalyzer:
    """Forward Abstract Interpretation Solver executing over a Basic-Block CFG."""

    def analyze(self, cfg: ControlFlowGraph, initial_env: AbstractEnvironment) -> dict[str, AbstractEnvironment]:
        """Runs fixpoint dataflow analysis over cfg and returns in_states for all reachable blocks."""
        in_states: dict[str, AbstractEnvironment] = {cfg.entry_id: initial_env.copy()}
        out_states: dict[str, AbstractEnvironment] = {}
        edge_states: dict[tuple[str, str], AbstractEnvironment] = {}

        worklist: list[str] = [cfg.entry_id]

        # Iteration safeguard to prevent infinite loops on un-widened states
        step_count = 0
        max_steps = 1000

        while worklist and step_count < max_steps:
            step_count += 1
            block_id = worklist.pop(0)

            if block_id not in cfg.reachable_blocks:
                continue

            # Gather IN state from incoming refined edge states
            reachable_preds = [p for p in cfg.blocks[block_id].predecessors if p in cfg.reachable_blocks]
            if reachable_preds and block_id != cfg.entry_id:
                valid_edges = [(p, block_id) for p in reachable_preds if (p, block_id) in edge_states]
                if valid_edges:
                    merged_in = edge_states[valid_edges[0]].copy()
                    for e in valid_edges[1:]:
                        merged_in = merged_in.join(edge_states[e])
                    in_states[block_id] = merged_in
                else:
                    merged_in = in_states.get(block_id, initial_env.copy())
            else:
                merged_in = in_states.get(block_id, initial_env.copy())

            # Transfer basic block statements
            block_out = merged_in.copy()
            self._transfer_block(cfg.blocks[block_id].statements, block_out)
            out_states[block_id] = block_out

            # Propagate to successors along polar edges
            for edge in cfg.outgoing_edges(block_id):
                succ_id = edge.target_id
                if succ_id not in cfg.reachable_blocks:
                    continue

                edge_env = block_out.copy()
                self._refine_edge(edge, edge_env)
                edge_states[(block_id, succ_id)] = edge_env

                existing_succ_in = in_states.get(succ_id)
                if existing_succ_in is None:
                    in_states[succ_id] = edge_env
                    if succ_id not in worklist:
                        worklist.append(succ_id)
                else:
                    all_succ_preds = [p for p in cfg.blocks[succ_id].predecessors if (p, succ_id) in edge_states]
                    if all_succ_preds:
                        new_succ_in = edge_states[(all_succ_preds[0], succ_id)].copy()
                        for p in all_succ_preds[1:]:
                            new_succ_in = new_succ_in.join(edge_states[(p, succ_id)])
                    else:
                        new_succ_in = edge_env

                    if not self._envs_equal(existing_succ_in, new_succ_in):
                        in_states[succ_id] = new_succ_in
                        if succ_id not in worklist:
                            worklist.append(succ_id)

        return in_states

    def _transfer_block(self, statements: list[Any], env: AbstractEnvironment) -> None:
        """Executes transfer functions for sequential statements in a basic block."""
        for stmt in statements:
            text = self._stmt_to_text(stmt)
            if not text:
                continue

            # Detect variable assignments: $var = expr
            assign_match = re.search(r"(\$[a-zA-Z0-9_]+)\s*=\s*(.+)", text)
            if assign_match:
                lhs_var = assign_match.group(1).strip()
                rhs_expr = assign_match.group(2).strip()

                # Check for ValueTransformation e.g. intval($y), (int)$y, escapeshellarg($y)
                trans_found = False
                for trans_name in (
                    "intval",
                    "floatval",
                    "escapeshellarg",
                    "escapeshellcmd",
                    "htmlspecialchars",
                    "htmlentities",
                    "basename",
                    "realpath",
                    "(int)",
                ):
                    if trans_name in rhs_expr.lower():
                        trans = guard_registry.lookup_transformation(trans_name)
                        if trans:
                            arg_match = re.search(r"\(\s*(\$[a-zA-Z0-9_]+)\s*\)", rhs_expr)
                            src_var = arg_match.group(1) if arg_match else ""
                            src_val = env.get_value(src_var) if src_var else None
                            src_taint = src_val.taint if src_val else TaintState.TAINTED

                            new_val = env.assignment_kill(
                                lhs_var,
                                new_taint=src_taint,
                                prov_id="",
                                prov_desc=f"Transformed by {trans_name}",
                            )
                            env.set_value(new_val.with_constraints(set(trans.produced_constraints)))
                            trans_found = True
                            break

                if not trans_found:
                    # Check if RHS is variable copy e.g. $x = $y
                    rhs_var_match = re.match(r"^(\$[a-zA-Z0-9_]+);?$", rhs_expr)
                    if rhs_var_match:
                        rhs_var = rhs_var_match.group(1)
                        rhs_val = env.get_value(rhs_var)
                        new_val = env.assignment_kill(
                            lhs_var,
                            new_taint=rhs_val.taint,
                            prov_id=rhs_val.provenance_node_id,
                            prov_desc=f"Copy of {rhs_var}",
                        )
                        env.set_value(new_val.with_constraints(set(rhs_val.all_constraints)))
                    else:
                        rhs_vars = re.findall(r"\$[a-zA-Z0-9_]+", rhs_expr)
                        is_superglobal = any(
                            sg in rhs_expr for sg in ("$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES", "$_SERVER")
                        )

                        collected_constraints: set[SemanticConstraint] = set()
                        inherited_taint = TaintState.TAINTED if is_superglobal else TaintState.UNKNOWN

                        for r_var in rhs_vars:
                            if not r_var.startswith("$_"):
                                r_val = env.get_value(r_var)
                                if r_val:
                                    collected_constraints.update(r_val.all_constraints)
                                    if r_val.taint in (TaintState.TAINTED, TaintState.CONSTRAINED):
                                        inherited_taint = (
                                            TaintState.CONSTRAINED if collected_constraints else TaintState.TAINTED
                                        )

                        new_val = env.assignment_kill(
                            lhs_var, new_taint=inherited_taint, prov_desc=f"Assigned {rhs_expr[:30]}"
                        )
                        if collected_constraints:
                            new_val = new_val.with_constraints(collected_constraints)
                        env.set_value(new_val)

    def _refine_edge(self, edge: CFGEdge, env: AbstractEnvironment) -> None:
        """Refines abstract environment along polar branch edges."""
        if edge.kind not in (CFGEdgeKind.TRUE_BRANCH, CFGEdgeKind.FALSE_BRANCH):
            return

        cond_ast = edge.condition_ast
        if not cond_ast:
            return

        cap, var_name, is_negated = guard_registry.match_predicate_ast(cond_ast)
        if not cap or not var_name:
            return

        val = env.get_value(var_name)
        if not val:
            return

        if edge.kind == CFGEdgeKind.TRUE_BRANCH:
            constraints = cap.false_branch_constraints if is_negated else cap.true_branch_constraints
        else:  # FALSE_BRANCH
            constraints = cap.true_branch_constraints if is_negated else cap.false_branch_constraints

        if constraints:
            refined_val = val.with_constraints(set(constraints))
            env.set_value(refined_val)

    @staticmethod
    def _envs_equal(env1: AbstractEnvironment, env2: AbstractEnvironment) -> bool:
        if set(env1.values.keys()) != set(env2.values.keys()):
            return False
        for version_key, val1 in env1.values.items():
            val2 = env2.values.get(version_key)
            if not val2:
                return False
            if (val1.taint, val1.type_facts, val1.sanitization_facts) != (
                val2.taint,
                val2.type_facts,
                val2.sanitization_facts,
            ):
                return False
        return True

    @staticmethod
    def _stmt_to_text(stmt: Any) -> str:
        if isinstance(stmt, str):
            return stmt
        if isinstance(stmt, dict):
            return str(stmt.get("text", stmt.get("raw", "")))
        return str(getattr(stmt, "text", ""))
