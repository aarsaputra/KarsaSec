"""Static Single Assignment (SSA) Models and Phi Node definitions."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SSAVar:
    """Represents a versioned variable in SSA form (e.g. x_1, x_2)."""

    base_name: str
    version: int

    @property
    def ssa_name(self) -> str:
        return f"{self.base_name}_{self.version}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "base_name": self.base_name,
            "version": self.version,
            "ssa_name": self.ssa_name,
        }


@dataclass
class PhiNode:
    """Represents a Phi (Φ) node joining multiple variable versions at control flow join points."""

    target_var: SSAVar
    operand_vars: list[SSAVar] = field(default_factory=list)
    basic_block_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_var": self.target_var.to_dict(),
            "operand_vars": [v.to_dict() for v in self.operand_vars],
            "basic_block_id": self.basic_block_id,
        }


@dataclass
class SSANode:
    """Node in an SSA graph representing an assignment or expression with SSA variables."""

    id: str
    line_number: int
    target: SSAVar | None = None
    phi_node: PhiNode | None = None
    use_vars: list[SSAVar] = field(default_factory=list)
    label: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "line_number": self.line_number,
            "target": self.target.to_dict() if self.target else None,
            "phi_node": self.phi_node.to_dict() if self.phi_node else None,
            "use_vars": [v.to_dict() for v in self.use_vars],
            "label": self.label,
        }


@dataclass
class SSAFunction:
    """SSA form representation of a function."""

    function_name: str
    file_path: str
    nodes: list[SSANode] = field(default_factory=list)
    phi_nodes: list[PhiNode] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "function_name": self.function_name,
            "file_path": self.file_path,
            "nodes": [n.to_dict() for n in self.nodes],
            "phi_nodes": [p.to_dict() for p in self.phi_nodes],
        }
