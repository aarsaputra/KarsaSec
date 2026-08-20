"""Control Flow Graph (CFG) Model for Intraprocedural Analysis (E12-13).

Design Principles:
  - BasicBlock represents sequential AST nodes/statements with single entry and exit points.
  - CFGEdge records control-flow direction and branch polarity (FALLTHROUGH, TRUE_BRANCH, FALSE_BRANCH, LOOP_BACKEDGE).
  - ControlFlowGraph maintains entry/exit node identifiers, block mappings, edge lists, reachability sets, and dominator sets.
  - Anti-hardcoding: Language-agnostic, rule-agnostic, pure graph model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class CFGEdgeKind(StrEnum):
    """Polared control flow edge types."""

    FALLTHROUGH = "FALLTHROUGH"
    TRUE_BRANCH = "TRUE_BRANCH"
    FALSE_BRANCH = "FALSE_BRANCH"
    LOOP_BACKEDGE = "LOOP_BACKEDGE"


@dataclass(slots=True)
class CFGEdge:
    """Directed edge between basic blocks in the CFG."""

    src_id: str
    target_id: str
    kind: CFGEdgeKind = CFGEdgeKind.FALLTHROUGH
    condition_ast: Any | None = None


@dataclass(slots=True)
class BasicBlock:
    """A sequential basic block of statements within a control flow graph."""

    block_id: str
    label: str = ""
    statements: list[Any] = field(default_factory=list)
    predecessors: list[str] = field(default_factory=list)
    successors: list[str] = field(default_factory=list)
    is_entry: bool = False
    is_exit: bool = False
    is_terminate: bool = False  # True for exit(), die(), return, throw


@dataclass(slots=True)
class ControlFlowGraph:
    """Intraprocedural Control Flow Graph representation."""

    name: str
    entry_id: str
    exit_id: str
    blocks: dict[str, BasicBlock] = field(default_factory=dict)
    edges: list[CFGEdge] = field(default_factory=list)
    dominators: dict[str, set[str]] = field(default_factory=dict)
    reachable_blocks: set[str] = field(default_factory=set)

    def get_block(self, block_id: str) -> BasicBlock | None:
        return self.blocks.get(block_id)

    def outgoing_edges(self, src_id: str) -> list[CFGEdge]:
        return [e for e in self.edges if e.src_id == src_id]

    def incoming_edges(self, target_id: str) -> list[CFGEdge]:
        return [e for e in self.edges if e.target_id == target_id]

    def is_reachable(self, block_id: str) -> bool:
        return block_id in self.reachable_blocks

    def dominates(self, dom_id: str, block_id: str) -> bool:
        """Return True if dom_id dominates block_id in this CFG."""
        return dom_id in self.dominators.get(block_id, set())
