"""Flow ↔ Handler / Route interprocedural semantic correlator."""

from __future__ import annotations

from karsasec.framework.framework_semantics.correlation.contracts import RelationshipCandidate
from karsasec.framework.framework_semantics.correlation.state import CorrelationState
from karsasec.framework.semantic_models import SemanticEdgeType


class FlowCorrelator:
    """Correlate FlowDefinition items with Route and Handler graph nodes in CorrelationState."""

    @staticmethod
    def correlate(state: CorrelationState) -> None:
        for flow_node_id, flow in state.flows_by_id.items():
            # 1. Link Route to Flow if route_id matches in scope
            if flow.scope.route_id:
                route_id = flow.scope.route_id
                if route_id in state.routes_by_id:
                    state.add_candidate(
                        RelationshipCandidate(
                            source_id=route_id,
                            target_id=flow_node_id,
                            edge_type=SemanticEdgeType.FLOWS_TO,
                            confidence=flow.confidence,
                            attributes={
                                "flow_id": flow.flow_id,
                                "scope_id": flow.scope.scope_id,
                            },
                        )
                    )

            # 2. Link Handler to Flow if handler_id matches in scope
            if flow.scope.handler_id:
                handler_id = flow.scope.handler_id
                if handler_id in state.handlers_by_id:
                    state.add_candidate(
                        RelationshipCandidate(
                            source_id=handler_id,
                            target_id=flow_node_id,
                            edge_type=SemanticEdgeType.PROPAGATES_TO,
                            confidence=flow.confidence,
                            attributes={
                                "flow_id": flow.flow_id,
                                "scope_id": flow.scope.scope_id,
                            },
                        )
                    )
