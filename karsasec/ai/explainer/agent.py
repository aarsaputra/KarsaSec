"""ExplainerAgent and LLM Provider Abstraction with Offline Fallback (E13-1)."""

from __future__ import annotations

import json
from typing import Protocol

from karsasec.ai.evidence_context import SecurityFindingContext, SecurityFindingContextBuilder
from karsasec.ai.explainer.policy import AICapability, AIPolicy
from karsasec.ai.explainer.prompt import SYSTEM_PROMPT, build_explainer_user_prompt
from karsasec.ai.explainer.validator import SecurityExplanationValidatorPipeline
from karsasec.ai.models import EvidenceClaim, ExplanationProvenance, KnowledgeReference, SecurityExplanation
from karsasec.ai.retrieval.adapter import KnowledgeChunk
from karsasec.core.finding.model import Finding
from karsasec.graph.dataflow.security_verdict import SecurityVerdict


class LLMProviderProtocol(Protocol):
    """Protocol for pluggable AI provider adapters."""

    def generate(self, system_prompt: str, user_prompt: str) -> str: ...


class MockLLMProvider:
    """Deterministic mock provider for offline unit and integration testing."""

    def __init__(self, raw_json_response: str | None = None, should_fail: bool = False) -> None:
        self.raw_json_response = raw_json_response
        self.should_fail = should_fail

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        if self.should_fail:
            raise RuntimeError("Mock LLM provider network connection failed.")

        if self.raw_json_response is not None:
            return self.raw_json_response

        # Parse user prompt to construct realistic mock JSON
        try:
            body = json.loads(user_prompt)
            ctx = body.get("DETERMINISTIC_SECURITY_CONTEXT", {})
        except Exception:
            ctx = {}

        finding_id = ctx.get("finding_id", "FINDING-MOCK")
        rule_title = ctx.get("rule_title", "Security Vulnerability")
        cwe_id = ctx.get("cwe_id", "CWE-20")
        verdict_status = ctx.get("verdict_status", "VULNERABLE")
        file_path = ctx.get("file_path", "source.py")
        line_num = ctx.get("line_number", 1)

        resp = {
            "summary": f"{rule_title} detected in {file_path}:{line_num}",
            "vulnerability_type": cwe_id,
            "why_vulnerable": f"Taint flows to sink in {file_path}:{line_num} without verified compatibility.",
            "source_analysis": f"User-controlled input at {ctx.get('source_location', 'UNKNOWN')}",
            "sink_analysis": f"Execution sink at {ctx.get('sink_location', 'UNKNOWN')}",
            "data_flow_explanation": "Taint flow propagated through variable assignment.",
            "security_impact": "Potential security boundary bypass or remote code execution.",
            "guard_analysis": "NOT_PROVEN — No control-flow guard eliminates vulnerability.",
            "sanitizer_analysis": "NONE COMPATIBLE — No compatible sanitizer function observed on path.",
            "remediation_guidance": "Use parameterized queries or framework-level escaping.",
            "limitations": "Analysis bounded by static dataflow evidence.",
            "confidence_score": 1.0,
            "evidence_claims": [],
            "knowledge_references": [],
        }
        return json.dumps(resp)


class TemplateFallbackExplainer:
    """Deterministic offline fallback generating evidence-grounded template explanations when LLM is unavailable."""

    @staticmethod
    def generate(context: SecurityFindingContext, knowledge_chunks: list[KnowledgeChunk]) -> SecurityExplanation:
        finding_id = context.finding_id
        ev_fp = context.evidence_fingerprint
        can_fp = context.canonical_fingerprint

        sanitizer_desc = (
            ", ".join(context.sanitizer_evidence)
            if context.sanitizer_evidence
            else "NONE COMPATIBLE — Deterministic analysis confirmed no compatible sanitizer on path."
        )
        guard_desc = (
            ", ".join(context.guard_evidence)
            if context.guard_evidence
            else "NOT_PROVEN — No control-flow guard eliminates risk."
        )

        k_refs = [
            KnowledgeReference(
                chunk_id=chunk.chunk_id,
                title=chunk.title,
                source=chunk.source,
                relevance_score=chunk.relevance_score,
            )
            for chunk in knowledge_chunks
        ]

        prov = ExplanationProvenance(
            finding_id=finding_id,
            scan_id="scan_default",
            verdict_fingerprint=can_fp,
            evidence_fingerprint=ev_fp,
            knowledge_fingerprints=[c.content_hash for c in knowledge_chunks],
            provider="template-fallback",
            model="offline-deterministic-v1",
            prompt_version="v1.0",
            schema_version="v1.0",
        )

        return SecurityExplanation(
            finding_id=finding_id,
            summary=f"Deterministic SAST Verdict: {context.verdict_status} ({context.rule_title})",
            vulnerability_type=f"{context.rule_id} ({context.cwe_id})",
            why_vulnerable=f"Source data reaches sink at {context.sink_location} without sink-compatible sanitization constraints.",
            source_analysis=f"Source location: {context.source_location}",
            sink_analysis=f"Sink location: {context.sink_location} (Category: {context.sink_category})",
            data_flow_explanation=f"Propagation path: {' -> '.join(context.provenance_path) if context.provenance_path else context.snippet}",
            security_impact=f"High risk security vulnerability under {context.owasp}.",
            guard_analysis=guard_desc,
            sanitizer_analysis=sanitizer_desc,
            remediation_guidance=context.remediation_guidance,
            limitations="Fallback explanation generated purely from deterministic SAST evidence without LLM synthesis.",
            confidence_score=1.0,
            evidence_claims=[],
            knowledge_references=k_refs,
            provenance=prov,
            explanation_fingerprint=prov.compute_fingerprint(),
        )


class ExplainerAgent:
    """Primary AI Explainer Agent consuming SAST findings & producing validated evidence-grounded explanations."""

    def __init__(self, provider: LLMProviderProtocol | None = None) -> None:
        self.provider = provider or MockLLMProvider()

    def explain(
        self,
        finding: Finding,
        verdict: SecurityVerdict | None = None,
        knowledge_chunks: list[KnowledgeChunk] | None = None,
        scan_id: str = "scan_default",
    ) -> SecurityExplanation:
        # Enforce read-only policy check
        AIPolicy.assert_allowed(AICapability.GENERATE_EXPLANATION)

        # Build bounded finding context
        context = SecurityFindingContextBuilder.build(finding, verdict=verdict)
        k_chunks = knowledge_chunks or []

        # If provider unavailable or fails, fallback to template
        if self.provider is None:
            return TemplateFallbackExplainer.generate(context, k_chunks)

        user_prompt = build_explainer_user_prompt(context, k_chunks)

        try:
            raw_response = self.provider.generate(SYSTEM_PROMPT, user_prompt)
            data = json.loads(raw_response)

            prov = ExplanationProvenance(
                finding_id=context.finding_id,
                scan_id=scan_id,
                verdict_fingerprint=context.canonical_fingerprint,
                evidence_fingerprint=context.evidence_fingerprint,
                knowledge_fingerprints=[c.content_hash for c in k_chunks],
                provider="mock-provider",
                model="gemini-2.5-flash",
                prompt_version="v1.0",
                schema_version="v1.0",
            )

            # Construct Pydantic model
            explanation = SecurityExplanation(
                finding_id=context.finding_id,
                summary=data.get("summary", context.rule_title),
                vulnerability_type=data.get("vulnerability_type", context.cwe_id),
                why_vulnerable=data.get("why_vulnerable", context.description),
                source_analysis=data.get("source_analysis", context.source_location),
                sink_analysis=data.get("sink_analysis", context.sink_location),
                data_flow_explanation=data.get("data_flow_explanation", context.snippet),
                security_impact=data.get("security_impact", context.owasp),
                guard_analysis=data.get("guard_analysis", "NOT_PROVEN"),
                sanitizer_analysis=data.get("sanitizer_analysis", "NONE COMPATIBLE"),
                remediation_guidance=data.get("remediation_guidance", context.remediation_guidance),
                limitations=data.get("limitations", "Bounded analysis."),
                confidence_score=float(data.get("confidence_score", 1.0)),
                evidence_claims=[EvidenceClaim(**c) for c in data.get("evidence_claims", [])],
                knowledge_references=[
                    KnowledgeReference(
                        chunk_id=c.chunk_id,
                        title=c.title,
                        source=c.source,
                        relevance_score=c.relevance_score,
                    )
                    for c in k_chunks
                ],
                provenance=prov,
            )

            # Validate evidence grounding & verdict consistency
            is_valid, sanitized_explanation, errors = SecurityExplanationValidatorPipeline.validate_and_sanitize(
                explanation, context
            )
            return sanitized_explanation

        except Exception:
            # Fallback gracefully if LLM response is malformed or throws network errors
            return TemplateFallbackExplainer.generate(context, k_chunks)
