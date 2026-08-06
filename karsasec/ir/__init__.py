"""KarsaSec Universal Intermediate Representation (IR) Engine.

Unifies AST representations across programming languages into a single language-agnostic
IR representation for semantic analysis, control flow graphs, and predicate evaluation.
"""

from karsasec.ir.builder import IRBuilder
from karsasec.ir.nodes import (
    IRAssignment,
    IRCall,
    IRExpression,
    IRFunction,
    IRIf,
    IRLoop,
    IRNode,
    IRReturn,
    IRStatement,
)

__all__ = [
    "IRNode",
    "IRExpression",
    "IRCall",
    "IRStatement",
    "IRAssignment",
    "IRReturn",
    "IRIf",
    "IRLoop",
    "IRFunction",
    "IRBuilder",
]
