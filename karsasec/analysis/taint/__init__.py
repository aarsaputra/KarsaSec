"""KarsaSec Intraprocedural Taint Analysis Engine Module."""

from karsasec.analysis.taint.engine import IntraproceduralTaintEngine
from karsasec.analysis.taint.models import (
    TaintCategory,
    TaintEdge,
    TaintGraph,
    TaintNode,
    TaintPath,
    TaintSanitizer,
    TaintSink,
    TaintSource,
    TaintState,
)
from karsasec.analysis.taint.propagator import TaintPropagator
from karsasec.analysis.taint.reporter import TaintReporter
from karsasec.analysis.taint.sanitizers import SanitizerRegistry
from karsasec.analysis.taint.sinks import SinkRegistry
from karsasec.analysis.taint.sources import SourceRegistry
from karsasec.analysis.taint.taint_pass import TaintPass

__all__ = [
    "TaintState",
    "TaintCategory",
    "TaintSource",
    "TaintSink",
    "TaintSanitizer",
    "TaintNode",
    "TaintEdge",
    "TaintPath",
    "TaintGraph",
    "SourceRegistry",
    "SinkRegistry",
    "SanitizerRegistry",
    "TaintPropagator",
    "IntraproceduralTaintEngine",
    "TaintReporter",
    "TaintPass",
]
