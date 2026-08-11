"""Flask Semantic Correlator orchestrating the 4-phase lifecycle: collect -> correlate -> validate -> emit."""

from __future__ import annotations

from dataclasses import dataclass

from karsasec.framework.diagnostics import ErrorCode, SemanticDiagnostic
from karsasec.framework.factories import FrameworkNodeFactory
from karsasec.framework.framework_semantics.correlation.auth_correlator import AuthCorrelator
from karsasec.framework.framework_semantics.correlation.config_correlator import ConfigCorrelator
from karsasec.framework.framework_semantics.correlation.controller_correlator import ControllerCorrelator
from karsasec.framework.framework_semantics.correlation.diagnostics import create_orphan_diagnostic
from karsasec.framework.framework_semantics.correlation.flow_correlator import FlowCorrelator
from karsasec.framework.framework_semantics.correlation.graph_validator import GraphValidator
from karsasec.framework.framework_semantics.correlation.middleware_correlator import MiddlewareCorrelator
from karsasec.framework.framework_semantics.correlation.normalizer import GraphNormalizer
from karsasec.framework.framework_semantics.correlation.route_correlator import RouteCorrelator
from karsasec.framework.framework_semantics.correlation.state import CorrelationState
from karsasec.framework.intermediate import IntermediateSemanticRepresentation
from karsasec.framework.semantic_models import FrameworkSemanticGraph


@dataclass(frozen=True)
class CorrelationResult:
    """Immutable result container returned by FlaskSemanticCorrelator."""
    graph: FrameworkSemanticGraph
    diagnostics: tuple[SemanticDiagnostic, ...]
    is_valid: bool


class FlaskSemanticCorrelator:
    """Compiler-grade deterministic Flask Semantic Correlator (Sprint E10-3C)."""

    def run(self, isr: IntermediateSemanticRepresentation) -> CorrelationResult:
        """Execute the 4-pass correlation pipeline: collect -> correlate -> validate -> emit."""
        # 1. Collect Phase
        state = self.collect(isr)

        # 2. Correlate Phase
        self.correlate(state)

        # 3. Check for Orphan Entities (Phase 10 Diagnostic Checks)
        self._check_orphans(state)

        # 4. Validate Phase
        is_valid = GraphValidator.validate(state)

        # 5. Emit Phase (No resolution or mutation happens in emit!)
        graph = self.emit(state)

        return CorrelationResult(
            graph=graph,
            diagnostics=tuple(state.diagnostics),
            is_valid=is_valid,
        )

    def collect(self, isr: IntermediateSemanticRepresentation) -> CorrelationState:
        """Phase 1: Build semantic graph nodes and index lookup tables from ISR."""
        state = CorrelationState(isr=isr)

        # Process Routes
        for r in isr.routes:
            node = FrameworkNodeFactory.create_route_node(r)
            state.add_node(node)
            state.routes_by_id[node.id] = r

        # Process Handlers
        for h in isr.handlers:
            node = FrameworkNodeFactory.create_handler_node(h)
            state.add_node(node)
            state.handlers_by_id[node.id] = h
            state.handlers_by_name.setdefault(h.name, []).append(h)
            state.handlers_by_name.setdefault(h.function_name, []).append(h)

        # Process Controllers
        for c in isr.controllers:
            node = FrameworkNodeFactory.create_controller_node(c)
            state.add_node(node)
            state.controllers_by_id[node.id] = c
            state.controllers_by_name.setdefault(c.name, []).append(c)

        # Process Middlewares
        for m in isr.middlewares:
            node = FrameworkNodeFactory.create_middleware_node(m)
            state.add_node(node)
            state.middlewares_by_id[node.id] = m

        # Process Auths
        for a in isr.auths:
            node = FrameworkNodeFactory.create_auth_node(a)
            state.add_node(node)
            state.auths_by_id[node.id] = a

        # Process Configs
        for cfg in isr.configs:
            node = FrameworkNodeFactory.create_config_node(cfg)
            state.add_node(node)
            state.configs_by_id[node.id] = cfg

        # Process Flows
        for f in isr.flows:
            node = FrameworkNodeFactory.create_flow_node(f)
            state.add_node(node)
            state.flows_by_id[node.id] = f

        return state

    def correlate(self, state: CorrelationState) -> None:
        """Phase 2: Perform domain correlation passes."""
        RouteCorrelator.correlate(state)
        ControllerCorrelator.correlate(state)
        MiddlewareCorrelator.correlate(state)
        AuthCorrelator.correlate(state)
        ConfigCorrelator.correlate(state)
        FlowCorrelator.correlate(state)

    def _check_orphans(self, state: CorrelationState) -> None:
        """Check for unlinked orphan entities and emit Severity.INFO diagnostics."""
        bound_targets = {cand.target_id for cand in state.candidates}
        bound_sources = {cand.source_id for cand in state.candidates}
        bound_all = bound_targets.union(bound_sources)

        # Check orphan handlers
        for h_id, h in state.handlers_by_id.items():
            if h_id not in bound_all:
                state.add_diagnostic(
                    create_orphan_diagnostic(
                        code=ErrorCode.ORPHAN_HANDLER,
                        entity_name=h.name,
                        location=h.origin.location_info,
                        evidence=f"Handler '{h.name}' is not referenced by any Route or Controller",
                    )
                )

        # Check orphan controllers
        for c_id, c in state.controllers_by_id.items():
            if c_id not in bound_all:
                state.add_diagnostic(
                    create_orphan_diagnostic(
                        code=ErrorCode.ORPHAN_CONTROLLER,
                        entity_name=c.name,
                        location=c.origin.location_info,
                        evidence=f"Controller '{c.name}' is not bound to any Route or Handler",
                    )
                )

    def emit(self, state: CorrelationState) -> FrameworkSemanticGraph:
        """Phase 3: Transform state into canonical, immutable FrameworkSemanticGraph."""
        return GraphNormalizer.normalize(state)
