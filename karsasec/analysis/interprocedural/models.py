"""Interprocedural Taint Data Models, Call Contexts, Function Summaries, and Cross-Function Paths."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from karsasec.analysis.taint.models import TaintCategory, TaintNode


@dataclass
class CallSite:
    """Represents a function call location within a caller function."""

    caller_id: str
    callee_name: str
    arguments: list[str] = field(default_factory=list)
    line_number: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "caller_id": self.caller_id,
            "callee_name": self.callee_name,
            "arguments": self.arguments,
            "line_number": self.line_number,
        }


@dataclass
class CallContext:
    """Call context stack tracking 1-call-site or k-call-site sensitivity."""

    call_stack: list[str] = field(default_factory=list)

    @property
    def depth(self) -> int:
        return len(self.call_stack)

    def push(self) -> CallContext:
        """Pushes a call frame and returns a new context object."""
        return CallContext(call_stack=list(self.call_stack))

    def contains(self, fn_name: str) -> bool:
        return fn_name in self.call_stack

    def to_dict(self) -> dict[str, Any]:
        return {"call_stack": self.call_stack, "depth": self.depth}


@dataclass
class ParameterSummary:
    """Summary of how a function parameter behaves regarding taint."""

    param_name: str
    index: int
    is_tainted: bool = False
    sanitized_by: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "param_name": self.param_name,
            "index": self.index,
            "is_tainted": self.is_tainted,
            "sanitized_by": self.sanitized_by,
        }


@dataclass
class ReturnSummary:
    """Summary of a function's return value taint behavior."""

    is_tainted: bool = False
    sanitized_by: str = ""
    passthrough_params: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_tainted": self.is_tainted,
            "sanitized_by": self.sanitized_by,
            "passthrough_params": self.passthrough_params,
        }


@dataclass
class FunctionSummary:
    """Compact reusable summary of a function's taint contract."""

    function_name: str
    file_path: str = ""
    parameters: dict[int, ParameterSummary] = field(default_factory=dict)
    return_summary: ReturnSummary = field(default_factory=ReturnSummary)
    contains_source: bool = False
    contains_sink: bool = False
    contains_sanitizer: bool = False
    has_recursive_calls: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "function_name": self.function_name,
            "file_path": self.file_path,
            "parameters": {idx: p.to_dict() for idx, p in self.parameters.items()},
            "return_summary": self.return_summary.to_dict(),
            "contains_source": self.contains_source,
            "contains_sink": self.contains_sink,
            "contains_sanitizer": self.contains_sanitizer,
            "has_recursive_calls": self.has_recursive_calls,
        }


@dataclass
class InterproceduralTaintPath:
    """Cross-function taint flow path from initial Source to final Sink."""

    source_func: str
    sink_func: str
    call_chain: list[CallSite] = field(default_factory=list)
    source_node: TaintNode | None = None
    sink_node: TaintNode | None = None
    category: TaintCategory = TaintCategory.GENERIC
    is_vulnerable: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_func": self.source_func,
            "sink_func": self.sink_func,
            "call_chain": [cs.to_dict() for cs in self.call_chain],
            "source_node": self.source_node.to_dict() if self.source_node else None,
            "sink_node": self.sink_node.to_dict() if self.sink_node else None,
            "category": self.category.value,
            "is_vulnerable": self.is_vulnerable,
        }


class InterproceduralTaintGraph:
    """Graph container holding cross-function summaries and interprocedural taint paths."""

    def __init__(self) -> None:
        self.function_summaries: dict[str, FunctionSummary] = {}
        self.vulnerable_paths: list[InterproceduralTaintPath] = []
        self.safe_paths: list[InterproceduralTaintPath] = []

    def add_summary(self, summary: FunctionSummary) -> None:
        self.function_summaries[summary.function_name] = summary

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_summaries": len(self.function_summaries),
            "function_summaries": {name: s.to_dict() for name, s in self.function_summaries.items()},
            "vulnerable_paths": [p.to_dict() for p in self.vulnerable_paths],
            "safe_paths": [p.to_dict() for p in self.safe_paths],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
