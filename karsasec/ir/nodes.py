"""Universal Intermediate Representation (IR) Node Definitions for Multi-Language Analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class IRNode:
    """Base class for all language-agnostic IR nodes."""

    id: str
    line_number: int
    file_path: str
    language: str

    @property
    def line(self) -> int:
        return self.line_number

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "node_type": self.__class__.__name__,
            "line_number": self.line_number,
            "file_path": self.file_path,
            "language": self.language,
        }


@dataclass
class IRExpression(IRNode):
    """Represents an expression node in IR."""

    raw_expression: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d["raw_expression"] = self.raw_expression
        return d


@dataclass
class IRStatement(IRNode):
    """Represents a statement node in IR."""

    pass


@dataclass
class IRCall(IRExpression, IRStatement):
    """Represents a function or method invocation in IR."""

    callee_name: str = ""
    arguments: list[str] = field(default_factory=list)

    @property
    def callee(self) -> str:
        return self.callee_name

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d["callee_name"] = self.callee_name
        d["arguments"] = self.arguments
        return d


@dataclass
class IRVar:
    name: str


@dataclass
class IRAssignment(IRStatement):
    """Represents a variable assignment statement in IR."""

    target: str | IRVar = ""
    value_expression: Any = ""
    operator: str = "="

    @property
    def value(self) -> Any:
        return self.value_expression

    def __post_init__(self) -> None:
        if isinstance(self.target, str):
            self.target = IRVar(name=self.target)

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d["target"] = self.target.name if isinstance(self.target, IRVar) else self.target
        d["value_expression"] = str(self.value_expression)
        d["operator"] = self.operator
        return d


@dataclass
class IRReturn(IRStatement):
    """Represents a return statement in IR."""

    value_expression: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d["value_expression"] = self.value_expression
        return d


@dataclass
class IRIf(IRStatement):
    """Represents a conditional branching statement (if/else) in IR."""

    condition_expr: str = ""
    then_statements: list[IRStatement] = field(default_factory=list)
    else_statements: list[IRStatement] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d["condition_expr"] = self.condition_expr
        d["then_statements"] = [s.to_dict() for s in self.then_statements]
        d["else_statements"] = [s.to_dict() for s in self.else_statements]
        return d


@dataclass
class IRLoop(IRStatement):
    """Represents a loop construct (for/while/foreach) in IR."""

    loop_type: str = "FOR"
    condition_expr: str = ""
    body_statements: list[IRStatement] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d["loop_type"] = self.loop_type
        d["condition_expr"] = self.condition_expr
        d["body_statements"] = [s.to_dict() for s in self.body_statements]
        return d


@dataclass
class IRFunction(IRNode):
    """Represents a top-level function or method declaration in IR."""

    name: str = ""
    parameters: list[str] = field(default_factory=list)
    body_statements: list[IRStatement] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d["name"] = self.name
        d["parameters"] = self.parameters
        d["body_statements"] = [s.to_dict() for s in self.body_statements]
        return d
