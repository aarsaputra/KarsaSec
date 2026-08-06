"""Generic Intermediate Representation (IR) node definitions."""

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class IRNode:
    """Base class for all Generic IR nodes."""
    node_id: str
    line: int = 0
    column: int = 0


@dataclass(frozen=True)
class IRVar(IRNode):
    """Represents a variable identifier in IR."""
    name: str = ""


@dataclass(frozen=True)
class IRLiteral(IRNode):
    """Represents a constant literal value in IR."""
    value: Any = None


@dataclass(frozen=True)
class IRAssign(IRNode):
    """Represents an assignment statement in IR."""
    target: IRVar = field(default_factory=lambda: IRVar(node_id="var_tmp"))
    value: IRNode = field(default_factory=lambda: IRLiteral(node_id="lit_tmp"))


@dataclass(frozen=True)
class IRCall(IRNode):
    """Represents a function or method invocation in IR."""
    callee: str = ""
    args: list[IRNode] = field(default_factory=list)


@dataclass(frozen=True)
class IRBinaryOp(IRNode):
    """Represents a binary operator operation in IR."""
    op: str = ""
    left: IRNode = field(default_factory=lambda: IRLiteral(node_id="lit_l"))
    right: IRNode = field(default_factory=lambda: IRLiteral(node_id="lit_r"))


@dataclass(frozen=True)
class IRBlock(IRNode):
    """Represents a basic block of IR statements."""
    statements: list[IRNode] = field(default_factory=list)
