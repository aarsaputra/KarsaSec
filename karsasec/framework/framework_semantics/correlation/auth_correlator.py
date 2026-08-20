"""Auth ↔ Route / Handler semantic correlator."""

from __future__ import annotations

from karsasec.framework.diagnostics import ErrorCode
from karsasec.framework.framework_semantics.correlation.policy import RelationshipPolicy
from karsasec.framework.framework_semantics.correlation.resolver import RelationshipResolver
from karsasec.framework.framework_semantics.correlation.state import CorrelationState
from karsasec.framework.semantic_models import SemanticEdgeType


class AuthCorrelator:
    """Correlate AuthDefinition items to RouteDefinition or HandlerDefinition items."""

    @staticmethod
    def correlate(state: CorrelationState) -> None:
        for auth_id, auth in state.auths_by_id.items():
            # Auth ↔ Handler matching
            if auth.handler:
                res = RelationshipResolver.resolve_target(
                    target_ref=auth.handler,
                    state=state,
                    candidate_pool=state.handlers_by_id,
                    name_index=state.handlers_by_name,
                    explicit_ref_attr="function_name",
                )

                RelationshipPolicy.apply_policy(
                    source_id=auth_id,
                    target_ref=auth.handler,
                    edge_type=SemanticEdgeType.PROTECTS,
                    resolution_result=res,
                    state=state,
                    unresolved_code=ErrorCode.UNRESOLVED_AUTH_BINDING,
                    ambiguous_code=ErrorCode.AMBIGUOUS_CONTROLLER,
                    confidence=auth.confidence,
                    evidence=(f"Auth policy '{auth.auth_type}' protects handler '{auth.handler}'",),
                    attributes={
                        "auth_type": auth.auth_type,
                        "scheme": auth.scheme,
                        "roles": list(auth.roles),
                        "permissions": list(auth.permissions),
                    },
                )

            # Auth ↔ Protected Routes matching
            for path_pattern in auth.protected_routes:
                for route_id, route in state.routes_by_id.items():
                    if route.path == path_pattern or (
                        path_pattern.endswith("*") and route.path.startswith(path_pattern[:-1])
                    ):
                        from karsasec.framework.framework_semantics.correlation.contracts import (
                            RelationshipCandidate,
                            ResolutionMethod,
                            ResolutionStatus,
                        )

                        candidate = RelationshipCandidate(
                            source_id=auth_id,
                            target_id=route_id,
                            edge_type=SemanticEdgeType.PROTECTS,
                            status=ResolutionStatus.RESOLVED,
                            resolution_method=ResolutionMethod.TIER5_EXPLICIT_METADATA,
                            confidence=auth.confidence,
                            evidence=(f"Auth policy '{auth.auth_type}' protects route '{route.method} {route.path}'",),
                            attributes={
                                "auth_type": auth.auth_type,
                                "path_pattern": path_pattern,
                                "roles": list(auth.roles),
                            },
                        )
                        state.add_candidate(candidate)
