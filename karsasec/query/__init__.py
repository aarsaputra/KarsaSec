"""CPG Query Engine Package for KarsaSec."""

from __future__ import annotations

from karsasec.query.ast import ExecutionPlanNode, PredicateNode, QueryNode, QueryStep, StepType
from karsasec.query.cache import QueryCache
from karsasec.query.context import ExecutionContext, ExecutionMetrics
from karsasec.query.dsl import Edge, File, Function, Literal, Module, Node, Package, Sanitizer, Sink, Source, Variable
from karsasec.query.executor import QueryExecutor
from karsasec.query.explain import EvidenceChain, EvidenceTree, ExplainEngine
from karsasec.query.optimizer import QueryOptimizer
from karsasec.query.planner import QueryPlanner
from karsasec.query.predicates import (
    AND,
    CONTAINS,
    COUNT,
    EXISTS,
    IN,
    NOT,
    NOT_IN,
    OR,
    REGEX,
    PredicateEngine,
)
from karsasec.query.profiler import QueryProfiler
from karsasec.query.traversal_engine import MultiHopTraversalEngine

__all__ = [
    "StepType",
    "PredicateNode",
    "QueryStep",
    "QueryNode",
    "ExecutionPlanNode",
    "Node",
    "Function",
    "Variable",
    "File",
    "Module",
    "Package",
    "Source",
    "Sink",
    "Sanitizer",
    "Edge",
    "Literal",
    "PredicateEngine",
    "AND",
    "OR",
    "NOT",
    "EXISTS",
    "COUNT",
    "REGEX",
    "CONTAINS",
    "IN",
    "NOT_IN",
    "QueryPlanner",
    "QueryOptimizer",
    "ExecutionContext",
    "ExecutionMetrics",
    "QueryExecutor",
    "MultiHopTraversalEngine",
    "QueryCache",
    "EvidenceChain",
    "EvidenceTree",
    "ExplainEngine",
    "QueryProfiler",
]
