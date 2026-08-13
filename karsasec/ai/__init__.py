"""KarsaSec AI Consumer Layer package."""

from karsasec.ai.artifacts import ScanArtifactContainer, SecurityArtifactReader
from karsasec.ai.evidence_context import SecurityFindingContext, SecurityFindingContextBuilder
from karsasec.ai.explainer.agent import ExplainerAgent, MockLLMProvider, TemplateFallbackExplainer
from karsasec.ai.models import EvidenceClaim, ExplanationProvenance, KnowledgeReference, SecurityExplanation

__all__ = [
    "EvidenceClaim",
    "ExplainerAgent",
    "ExplanationProvenance",
    "KnowledgeReference",
    "MockLLMProvider",
    "ScanArtifactContainer",
    "SecurityArtifactReader",
    "SecurityExplanation",
    "SecurityFindingContext",
    "SecurityFindingContextBuilder",
    "TemplateFallbackExplainer",
]
