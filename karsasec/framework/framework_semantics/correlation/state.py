"""CorrelationState accumulator for correlation pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field

from karsasec.framework.diagnostics import SemanticDiagnostic
from karsasec.framework.framework_semantics.correlation.contracts import RelationshipCandidate
from karsasec.framework.intermediate import (
    AuthDefinition,
    ConfigDefinition,
    ControllerDefinition,
    FlowDefinition,
    HandlerDefinition,
    IntermediateSemanticRepresentation,
    MiddlewareDefinition,
    RouteDefinition,
)
from karsasec.framework.semantic_models import FrameworkSemanticNode


@dataclass
class CorrelationState:
    """Accumulator holding state across collect, correlate, validate, and emit passes."""

    isr: IntermediateSemanticRepresentation
    nodes: dict[str, FrameworkSemanticNode] = field(default_factory=dict)
    candidates: list[RelationshipCandidate] = field(default_factory=list)
    diagnostics: list[SemanticDiagnostic] = field(default_factory=list)

    # Fast Indexing Tables (Built during collect pass)
    routes_by_id: dict[str, RouteDefinition] = field(default_factory=dict)
    handlers_by_id: dict[str, HandlerDefinition] = field(default_factory=dict)
    handlers_by_name: dict[str, list[HandlerDefinition]] = field(default_factory=dict)
    handlers_by_qual_name: dict[str, list[HandlerDefinition]] = field(default_factory=dict)
    controllers_by_id: dict[str, ControllerDefinition] = field(default_factory=dict)
    controllers_by_name: dict[str, list[ControllerDefinition]] = field(default_factory=dict)
    middlewares_by_id: dict[str, MiddlewareDefinition] = field(default_factory=dict)
    auths_by_id: dict[str, AuthDefinition] = field(default_factory=dict)
    configs_by_id: dict[str, ConfigDefinition] = field(default_factory=dict)
    flows_by_id: dict[str, FlowDefinition] = field(default_factory=dict)

    def add_node(self, node: FrameworkSemanticNode) -> None:
        """Register a semantic graph node in state."""
        self.nodes[node.id] = node

    def add_candidate(self, candidate: RelationshipCandidate) -> None:
        """Register a relationship candidate in state."""
        self.candidates.append(candidate)

    def add_diagnostic(self, diagnostic: SemanticDiagnostic) -> None:
        """Register a semantic diagnostic in state."""
        self.diagnostics.append(diagnostic)
