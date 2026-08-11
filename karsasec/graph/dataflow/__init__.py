"""KarsaSec Incremental Data-Flow Analysis Engine (E11)."""

from karsasec.graph.dataflow.analyzer import DataFlowAnalyzer, dataflow_analyzer
from karsasec.graph.dataflow.builder import DataFlowGraphBuilder, DefUseExtractor
from karsasec.graph.dataflow.legacy import (
    DataflowEdge,
    DataflowEdgeType,
    DataflowEngine,
    DataflowNode,
    DataflowPath,
)
from karsasec.graph.dataflow.model import (
    DataFlowEvidence,
    FlowLocation,
    FlowNode,
    FlowNodeKind,
    TaintPathHop,
    TaintState,
)
from karsasec.graph.dataflow.sanitizers import SanitizerCapability, SanitizerRegistry, sanitizer_registry
from karsasec.graph.dataflow.sinks import SinkCategory, SinkRegistry, sink_registry
from karsasec.graph.dataflow.sources import SourceRegistry, source_registry

__all__ = [
    "DataFlowAnalyzer",
    "dataflow_analyzer",
    "DataFlowGraphBuilder",
    "DefUseExtractor",
    "DataFlowEvidence",
    "FlowLocation",
    "FlowNode",
    "FlowNodeKind",
    "TaintPathHop",
    "TaintState",
    "SanitizerCapability",
    "SanitizerRegistry",
    "sanitizer_registry",
    "SinkCategory",
    "SinkRegistry",
    "sink_registry",
    "SourceRegistry",
    "source_registry",
    "DataflowEdge",
    "DataflowEdgeType",
    "DataflowEngine",
    "DataflowNode",
    "DataflowPath",
]
