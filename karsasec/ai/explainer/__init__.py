"""Explainer module for AI Consumer layer."""

from karsasec.ai.explainer.agent import ExplainerAgent, MockLLMProvider, TemplateFallbackExplainer
from karsasec.ai.explainer.policy import AICapability, AIPolicy, AIPolicyViolationError
from karsasec.ai.explainer.prompt import SYSTEM_PROMPT, build_explainer_user_prompt
from karsasec.ai.explainer.validator import (
    EvidenceReferenceValidator,
    SecurityExplanationValidatorPipeline,
    VerdictConsistencyValidator,
)

__all__ = [
    "AICapability",
    "AIPolicy",
    "AIPolicyViolationError",
    "EvidenceReferenceValidator",
    "ExplainerAgent",
    "MockLLMProvider",
    "SYSTEM_PROMPT",
    "SecurityExplanationValidatorPipeline",
    "TemplateFallbackExplainer",
    "VerdictConsistencyValidator",
    "build_explainer_user_prompt",
]
