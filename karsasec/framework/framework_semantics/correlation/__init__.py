"""Flask Semantic Correlation Engine (Sprint E10-3C)."""

from karsasec.framework.framework_semantics.correlation.contracts import (
    RelationshipCandidate,
    ResolutionMethod,
    ResolutionStatus,
)
from karsasec.framework.framework_semantics.correlation.correlator import (
    CorrelationResult,
    FlaskSemanticCorrelator,
)
from karsasec.framework.framework_semantics.correlation.state import CorrelationState

__all__ = [
    "FlaskSemanticCorrelator",
    "CorrelationResult",
    "CorrelationState",
    "ResolutionStatus",
    "ResolutionMethod",
    "RelationshipCandidate",
]
