"""Route ↔ Handler semantic correlator."""

from __future__ import annotations

from karsasec.framework.diagnostics import ErrorCode
from karsasec.framework.framework_semantics.correlation.policy import RelationshipPolicy
from karsasec.framework.framework_semantics.correlation.resolver import RelationshipResolver
from karsasec.framework.framework_semantics.correlation.state import CorrelationState
from karsasec.framework.semantic_models import SemanticEdgeType


class RouteCorrelator:
    """Correlate RouteDefinition items to HandlerDefinition items."""

    @staticmethod
    def correlate(state: CorrelationState) -> None:
        for route_id, route in state.routes_by_id.items():
            if not route.handler:
                continue

            # Attempt to resolve handler target
            res = RelationshipResolver.resolve_target(
                target_ref=route.handler,
                state=state,
                candidate_pool=state.handlers_by_id,
                name_index=state.handlers_by_name,
                explicit_ref_attr="function_name",
            )

            RelationshipPolicy.apply_policy(
                source_id=route_id,
                target_ref=route.handler,
                edge_type=SemanticEdgeType.HANDLES,
                resolution_result=res,
                state=state,
                unresolved_code=ErrorCode.MISSING_HANDLER,
                ambiguous_code=ErrorCode.AMBIGUOUS_CONTROLLER,
                confidence=route.confidence,
                evidence=(f"Route '{route.method} {route.path}' handlers target '{route.handler}'",),
                attributes={"handler_name": route.handler, "path": route.path, "method": route.method},
            )
