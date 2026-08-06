"""KarsaSec Generic Intermediate Representation (IR) Engine.

Unifies AST representations across programming languages into a single language-agnostic
IR representation for semantic analysis, dataflow propagation, and predicate evaluation.
"""

from karsasec.ir.builder import IRBuilder
from karsasec.ir.nodes import IRAssign, IRBinaryOp, IRBlock, IRCall, IRLiteral, IRNode, IRVar

__all__ = [
    "IRNode",
    "IRBlock",
    "IRCall",
    "IRAssign",
    "IRVar",
    "IRLiteral",
    "IRBinaryOp",
    "IRBuilder",
]
