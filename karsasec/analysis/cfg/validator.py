"""CFGValidator module enforcing strict Control Flow Graph invariants."""

from __future__ import annotations

from collections import deque

from karsasec.analysis.cfg.models import CFG, CFGNodeType


class CFGValidationError(Exception):
    """Raised when a Control Flow Graph violates structural validation rules."""

    pass


class CFGValidator:
    """Enforces formal invariants on generated Control Flow Graphs (CFGs)."""

    def validate(self, cfg: CFG) -> bool:
        """Validates all invariants on the given CFG. Returns True if valid, raises CFGValidationError otherwise."""
        self._validate_entry_exit(cfg)
        self._validate_edges(cfg)
        self._validate_reachability(cfg)
        return True

    def _validate_entry_exit(self, cfg: CFG) -> None:
        entry_nodes = [n for n in cfg.nodes.values() if n.node_type == CFGNodeType.ENTRY]
        if len(entry_nodes) != 1:
            raise CFGValidationError(
                f"CFG for '{cfg.function_name}' must have exactly 1 ENTRY node, found {len(entry_nodes)}"
            )

        exit_nodes = [n for n in cfg.nodes.values() if n.node_type == CFGNodeType.EXIT]
        if len(exit_nodes) != 1:
            raise CFGValidationError(
                f"CFG for '{cfg.function_name}' must have exactly 1 EXIT node, found {len(exit_nodes)}"
            )

    def _validate_edges(self, cfg: CFG) -> None:
        for edge in cfg.edges:
            if edge.source_id not in cfg.nodes:
                raise CFGValidationError(f"CFG edge references missing source node ID '{edge.source_id}'")
            if edge.target_id not in cfg.nodes:
                raise CFGValidationError(f"CFG edge references missing target node ID '{edge.target_id}'")

        # Check non-entry nodes have predecessors, non-exit nodes have successors
        for nid, node in cfg.nodes.items():
            if node.node_type != CFGNodeType.ENTRY:
                preds = cfg.get_predecessors(nid)
                if not preds:
                    raise CFGValidationError(f"CFG contains orphan node '{nid}' with 0 predecessors")

            if node.node_type != CFGNodeType.EXIT:
                succs = cfg.get_successors(nid)
                if not succs:
                    raise CFGValidationError(f"CFG contains node '{nid}' with 0 successors")

    def _validate_reachability(self, cfg: CFG) -> None:
        if not cfg.entry_node_id:
            raise CFGValidationError("CFG missing entry node ID")

        visited: set[str] = set()
        queue = deque([cfg.entry_node_id])

        while queue:
            curr = queue.popleft()
            if curr in visited:
                continue
            visited.add(curr)
            for succ in cfg.get_successors(curr):
                if succ not in visited:
                    queue.append(succ)

        unreachable = set(cfg.nodes.keys()) - visited
        if unreachable:
            raise CFGValidationError(f"CFG contains {len(unreachable)} unreachable nodes: {unreachable}")
