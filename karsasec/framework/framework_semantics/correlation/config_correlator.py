"""Config ↔ Framework semantic correlator."""

from __future__ import annotations

from karsasec.framework.framework_semantics.correlation.contracts import (
    RelationshipCandidate,
    ResolutionMethod,
    ResolutionStatus,
)
from karsasec.framework.framework_semantics.correlation.state import CorrelationState
from karsasec.framework.semantic_models import SemanticEdgeType, SemanticNodeType


class ConfigCorrelator:
    """Correlate ConfigDefinition items to explicit Framework root node (if present)."""

    @staticmethod
    def correlate(state: CorrelationState) -> None:
        # Check if an explicit FRAMEWORK node exists in state
        framework_node_id = None
        for node_id, node in state.nodes.items():
            if node.node_type == SemanticNodeType.FRAMEWORK:
                framework_node_id = node_id
                break

        if not framework_node_id:
            # Per Contract Decision 2: Do NOT create synthetic APPLICATION/FRAMEWORK nodes.
            # Config nodes remain as standalone CONFIG nodes.
            return

        for cfg_id, cfg in state.configs_by_id.items():
            candidate = RelationshipCandidate(
                source_id=cfg_id,
                target_id=framework_node_id,
                edge_type=SemanticEdgeType.CONFIGURES,
                status=ResolutionStatus.RESOLVED,
                resolution_method=ResolutionMethod.TIER5_EXPLICIT_METADATA,
                confidence=cfg.confidence,
                evidence=(f"Config key '{cfg.key}' configures framework instance",),
                attributes={"key": cfg.key, "category": cfg.category, "source": cfg.source},
            )
            state.add_candidate(candidate)
