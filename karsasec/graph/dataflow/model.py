"""Data-Flow IR data structures, representations, and evidence models (E11)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from karsasec.rules.enums import Confidence, Severity


class FlowNodeKind(StrEnum):
    """Classification of data-flow graph nodes."""

    SOURCE = "SOURCE"
    ASSIGNMENT = "ASSIGNMENT"
    USE = "USE"
    TRANSFORM = "TRANSFORM"
    SANITIZER = "SANITIZER"
    SINK = "SINK"
    PARAMETER = "PARAMETER"
    CALL = "CALL"
    RETURN = "RETURN"
    CONSTANT = "CONSTANT"
    UNKNOWN = "UNKNOWN"


class TaintState(StrEnum):
    """Taint evaluation status of expressions and symbols."""

    STATIC = "STATIC"
    TAINTED = "TAINTED"
    SANITIZED = "SANITIZED"
    DYNAMIC = "DYNAMIC"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class FlowLocation:
    """Source location descriptor for a FlowNode."""

    file_path: Path | None = None
    line: int | None = None
    column: int | None = None

    def as_posix_str(self) -> str:
        loc = f"line {self.line}" if self.line is not None else "unknown line"
        if self.file_path:
            return f"{self.file_path.as_posix()}:{loc}"
        return loc


@dataclass(frozen=True, slots=True)
class FlowNode:
    """Node in the incremental data-flow graph."""

    node_id: str
    kind: FlowNodeKind
    symbol: str
    location: FlowLocation = field(default_factory=FlowLocation)
    expression: str = ""
    taint_state: TaintState = TaintState.UNKNOWN
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class TaintPathHop:
    """Individual propagation step in a data-flow taint trace."""

    step: int
    kind: FlowNodeKind
    symbol: str
    snippet: str
    location: FlowLocation
    description: str = ""


@dataclass(frozen=True, slots=True)
class DataFlowEvidence:
    """Comprehensive diagnostic evidence produced by data-flow analysis."""

    state: TaintState
    path: tuple[TaintPathHop, ...] = ()
    source_symbol: str = ""
    sink_symbol: str = ""
    sanitizer_capability: str = "NONE"
    adjusted_confidence: Confidence = Confidence.CONFIDENT
    adjusted_severity: Severity = Severity.HIGH
    reason: str = ""
    truncated: bool = False
    hop_count: int = 0
