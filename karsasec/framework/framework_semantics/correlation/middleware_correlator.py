"""Middleware ↔ Route semantic correlator."""

from __future__ import annotations

from karsasec.framework.framework_semantics.correlation.contracts import (
    RelationshipCandidate,
    ResolutionMethod,
    ResolutionStatus,
)
from karsasec.framework.framework_semantics.correlation.state import CorrelationState
from karsasec.framework.semantic_models import SemanticEdgeType


class MiddlewareCorrelator:
    """Correlate MiddlewareDefinition items to RouteDefinition items based on extracted scope."""

    @staticmethod
    def correlate(state: CorrelationState) -> None:
        for mw_id, mw in state.middlewares_by_id.items():
            if mw.scope == "global":
                # Propagate global scope to all routes
                for route_id, route in state.routes_by_id.items():
                    candidate = RelationshipCandidate(
                        source_id=mw_id,
                        target_id=route_id,
                        edge_type=SemanticEdgeType.PROTECTS,
                        status=ResolutionStatus.RESOLVED,
                        resolution_method=ResolutionMethod.TIER5_EXPLICIT_METADATA,
                        confidence=mw.confidence,  # Derived from MiddlewareDefinition
                        evidence=(f"Global middleware '{mw.name}' applies to route '{route.method} {route.path}'",),
                        attributes={
                            "scope": "global",
                            "propagation": "inherited",
                            "middleware_name": mw.name,
                            "route_path": route.path,
                        },
                    )
                    state.add_candidate(candidate)

            elif mw.scope == "blueprint":
                # Propagate to routes under matching blueprint
                target_bp = mw.name.replace("_bp", "").replace("bp_", "")
                for route_id, route in state.routes_by_id.items():
                    route_bp = getattr(route, "blueprint", "")
                    if route_bp and (route_bp == target_bp or route_bp == mw.name):
                        candidate = RelationshipCandidate(
                            source_id=mw_id,
                            target_id=route_id,
                            edge_type=SemanticEdgeType.PROTECTS,
                            status=ResolutionStatus.RESOLVED,
                            resolution_method=ResolutionMethod.TIER5_EXPLICIT_METADATA,
                            confidence=mw.confidence,
                            evidence=(f"Blueprint middleware '{mw.name}' applies to route '{route.method} {route.path}'",),
                            attributes={
                                "scope": "blueprint",
                                "propagation": "inherited",
                                "middleware_name": mw.name,
                                "blueprint": route_bp,
                            },
                        )
                        state.add_candidate(candidate)

            elif mw.scope == "route" or mw.target_routes:
                # Direct route scope matching
                for target_route in mw.target_routes:
                    for route_id, route in state.routes_by_id.items():
                        if route.path == target_route or route.handler == target_route:
                            candidate = RelationshipCandidate(
                                source_id=mw_id,
                                target_id=route_id,
                                edge_type=SemanticEdgeType.PROTECTS,
                                status=ResolutionStatus.RESOLVED,
                                resolution_method=ResolutionMethod.TIER5_EXPLICIT_METADATA,
                                confidence=mw.confidence,
                                evidence=(f"Route middleware '{mw.name}' explicitly targets route '{route.method} {route.path}'",),
                                attributes={
                                    "scope": "route",
                                    "propagation": "direct",
                                    "middleware_name": mw.name,
                                    "target_route": target_route,
                                },
                            )
                            state.add_candidate(candidate)
