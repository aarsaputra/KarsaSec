"""Immutable Evidence and FindingEvidence models capturing provenance, taint paths, and constant resolutions (E12-3)."""

from dataclasses import dataclass, field
from typing import Any

from karsasec.graph.dataflow.model import TaintPathHop, TaintState


@dataclass(frozen=True)
class Evidence:
    """Immutable evidence representation containing vulnerable code snippet and context lines."""
    snippet: str
    line: int
    column: int
    context_lines: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class FindingEvidence:
    """Enriched evidence provenance capturing deep data-flow, sink semantics, and sanitizer details."""
    snippet: str
    line: int
    column: int
    sink_symbol: str = ""
    sink_category: str = "UNKNOWN"
    source_symbol: str = ""
    source_category: str = "UNKNOWN"
    taint_state: TaintState = TaintState.UNKNOWN
    constant_resolution: str = "UNKNOWN"
    sanitizer_symbol: str = ""
    sanitizer_capability: str = "NONE"
    taint_path: tuple[TaintPathHop, ...] = field(default_factory=tuple)
    ast_match: bool = True
    semantic_match: bool = False
    context_lines: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)
