"""Controller ↔ Handler semantic correlator."""

from __future__ import annotations

from karsasec.framework.diagnostics import ErrorCode
from karsasec.framework.framework_semantics.correlation.policy import RelationshipPolicy
from karsasec.framework.framework_semantics.correlation.resolver import RelationshipResolver
from karsasec.framework.framework_semantics.correlation.state import CorrelationState
from karsasec.framework.semantic_models import SemanticEdgeType


class ControllerCorrelator:
    """Correlate ControllerDefinition items to HandlerDefinition items."""

    @staticmethod
    def correlate(state: CorrelationState) -> None:
        for controller_id, controller in state.controllers_by_id.items():
            for handler_ref in controller.handlers:
                res = RelationshipResolver.resolve_target(
                    target_ref=handler_ref,
                    state=state,
                    candidate_pool=state.handlers_by_id,
                    name_index=state.handlers_by_name,
                    explicit_ref_attr="function_name",
                )

                RelationshipPolicy.apply_policy(
                    source_id=controller_id,
                    target_ref=handler_ref,
                    edge_type=SemanticEdgeType.DECLARES,
                    resolution_result=res,
                    state=state,
                    unresolved_code=ErrorCode.MISSING_HANDLER,
                    ambiguous_code=ErrorCode.AMBIGUOUS_CONTROLLER,
                    confidence=controller.confidence,
                    evidence=(f"Controller '{controller.name}' declares handler '{handler_ref}'",),
                    attributes={"controller_class": controller.class_name, "handler_name": handler_ref},
                )
