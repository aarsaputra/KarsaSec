"""Taint Analysis Data Models, TaintGraph containers, and Path representations."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class TaintState(StrEnum):
    UNTAINTED = "UNTAINTED"
    TAINTED = "TAINTED"
    SANITIZED = "SANITIZED"


class TaintCategory(StrEnum):
    SQL_INJECTION = "SQL_INJECTION"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    SSRF = "SSRF"
    XSS = "XSS"
    GENERIC = "GENERIC"


@dataclass
class TaintSource:
    """Represents an untrusted data entry point."""

    name: str
    language: str = "Python"
    line_number: int = 1
    pattern: str = ""
    category: str = "DIRECT"
    framework: str = "Java Servlet"
    is_user_controlled: bool = True

    @property
    def source_origin(self) -> str:
        return self.name or self.pattern or "UNKNOWN"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "language": self.language,
            "line_number": self.line_number,
            "pattern": self.pattern,
            "category": self.category,
            "framework": self.framework,
            "is_user_controlled": self.is_user_controlled,
        }


@dataclass
class TaintSink:
    """Represents a dangerous execution sink."""

    name: str
    category: TaintCategory = TaintCategory.GENERIC
    line_number: int = 1
    pattern: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category.value,
            "line_number": self.line_number,
            "pattern": self.pattern,
        }


@dataclass
class TaintSanitizer:
    """Represents a security cleaning/sanitization routine."""

    name: str
    category: TaintCategory = TaintCategory.GENERIC
    line_number: int = 1
    pattern: str = ""
    is_verified_safe: bool = True
    transformation_type: str = "ESCAPE"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category.value,
            "line_number": self.line_number,
            "pattern": self.pattern,
            "is_verified_safe": self.is_verified_safe,
            "transformation_type": str(self.transformation_type),
        }




@dataclass
class TaintNode:
    """Node in a TaintGraph representing a variable or statement's taint state."""

    id: str
    var_name: str
    state: TaintState = TaintState.UNTAINTED
    line_number: int = 1
    is_source: bool = False
    is_sink: bool = False
    is_sanitizer: bool = False
    label: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "var_name": self.var_name,
            "state": self.state.value,
            "line_number": self.line_number,
            "is_source": self.is_source,
            "is_sink": self.is_sink,
            "is_sanitizer": self.is_sanitizer,
            "label": self.label,
        }


@dataclass
class TaintEdge:
    """Edge in a TaintGraph representing taint flow between two nodes."""

    source_id: str
    target_id: str
    var_name: str = ""
    label: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "var_name": self.var_name,
            "label": self.label,
        }


@dataclass
class TaintPath:
    """Represents a complete flow path from Source to Sink."""

    source_node: TaintNode
    sink_node: TaintNode
    path_nodes: list[TaintNode] = field(default_factory=list)
    sanitizer_nodes: list[TaintNode] = field(default_factory=list)
    category: TaintCategory = TaintCategory.GENERIC
    is_vulnerable: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_node": self.source_node.to_dict(),
            "sink_node": self.sink_node.to_dict(),
            "path_nodes": [n.to_dict() for n in self.path_nodes],
            "sanitizer_nodes": [n.to_dict() for n in self.sanitizer_nodes],
            "category": self.category.value,
            "is_vulnerable": self.is_vulnerable,
        }


class TaintGraph:
    """Immutable TaintGraph containing all discovered taint flows for a function."""

    def __init__(self, function_name: str, file_path: str = "") -> None:
        self.function_name: str = function_name
        self.file_path: str = file_path
        self.nodes: dict[str, TaintNode] = {}
        self.edges: list[TaintEdge] = []
        self.vulnerable_paths: list[TaintPath] = []
        self.safe_paths: list[TaintPath] = []

    def add_node(self, node: TaintNode) -> None:
        self.nodes[node.id] = node

    def add_edge(self, source_id: str, target_id: str, var_name: str = "", label: str = "") -> None:
        self.edges.append(TaintEdge(source_id=source_id, target_id=target_id, var_name=var_name, label=label))

    def to_dict(self) -> dict[str, Any]:
        return {
            "function_name": self.function_name,
            "file_path": self.file_path,
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "vulnerable_paths": [p.to_dict() for p in self.vulnerable_paths],
            "safe_paths": [p.to_dict() for p in self.safe_paths],
            "nodes": {nid: n.to_dict() for nid, n in self.nodes.items()},
            "edges": [e.to_dict() for e in self.edges],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
