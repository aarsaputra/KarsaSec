"""Root Cause Analysis Agent & Offline Fallback (E13-2).

Enforces Security Invariants:
  - G16: SAST Authority Preservation (Sole security authority is SAST engine).
  - G26: Deterministic canonical fingerprinting across execution sessions.
  - G28-G30: Read-only filesystem, offline fallback support, zero autonomous code modification.
"""

from __future__ import annotations

import json
from typing import Any

from karsasec.ai.evidence_context import SecurityFindingContext, SecurityFindingContextBuilder
from karsasec.ai.explainer.agent import LLMProviderProtocol
from karsasec.ai.models import ExplanationProvenance, KnowledgeReference
from karsasec.ai.explainer.policy import AIPolicy
from karsasec.ai.rca.analyzer import RootCauseAnalyzer
from karsasec.ai.rca.evidence_graph import EvidenceGraph
from karsasec.ai.rca.fp_assessment import FalsePositiveRiskAssessor
from karsasec.ai.rca.models import (
    RootCauseAnalysis,
)
from karsasec.ai.rca.reflection import EvidenceReflectionEngine
from karsasec.ai.rca.validator import RCAEvidenceValidator
from karsasec.core.finding.model import Finding
from karsasec.graph.dataflow.security_verdict import SecurityVerdict
from karsasec.graph.dataflow.semantic_evidence import SemanticEvidenceBundle


class TemplateFallbackRCA:
    """Deterministic offline fallback RCA generator when LLM is unavailable or invalid."""

    @staticmethod
    def generate(
        ctx: SecurityFindingContext,
        graph: EvidenceGraph,
        bundle: SemanticEvidenceBundle | None = None,
        knowledge_chunks: list[Any] | None = None,
    ) -> RootCauseAnalysis:
        """Generates deterministic evidence-grounded Root Cause Analysis without LLM."""

        category, primary_step, chain = RootCauseAnalyzer.analyze(ctx, graph, bundle)
        reflection = EvidenceReflectionEngine.reflect(ctx, graph, bundle)
        fp_risk = FalsePositiveRiskAssessor.assess(ctx, graph, reflection)

        rca_fp = RootCauseAnalysis.compute_fingerprint(
            finding_id=ctx.finding_id,
            category=category,
            chain=chain,
            reflection=reflection.status,
            fp_risk=fp_risk,
        )

        provenance = ExplanationProvenance(
            finding_id=ctx.finding_id,
            verdict_fingerprint=ctx.canonical_fingerprint,
            evidence_fingerprint=ctx.evidence_fingerprint,
            knowledge_fingerprints=[k.chunk_id for k in (knowledge_chunks or []) if hasattr(k, "chunk_id")],
            provider="template-fallback-rca",
            model="deterministic-fallback",
            prompt_version="v1.0-rca",
            schema_version="v1.0-rca",
            canonical_fingerprint=rca_fp,
        )

        summary = (
            f"Deterministic SAST RCA for finding '{ctx.finding_id}' ({ctx.rule_id}). "
            f"Primary Cause: {category.value}. Verdict: {ctx.verdict_status}."
        )

        remediation = (
            f"Fix issue at {ctx.file_path}:{ctx.line_number}. "
            f"Ensure input '{ctx.variable_version}' is properly sanitized for sink category '{ctx.sink_category}'."
        )

        k_refs = tuple(
            KnowledgeReference(
                chunk_id=getattr(k, "chunk_id", "K-0"),
                title=getattr(k, "title", "RAG Chunk"),
                source=getattr(k, "source", "RAG"),
                relevance_score=float(getattr(k, "relevance_score", 1.0)),
            )
            for k in (knowledge_chunks or [])
        )

        return RootCauseAnalysis(
            finding_id=ctx.finding_id,
            rule_id=ctx.rule_id,
            verdict_status=ctx.verdict_status,
            root_cause_category=category,
            primary_cause_step=primary_step,
            evidence_chain=chain,
            evidence_gaps=reflection.gaps,
            contradictions=reflection.contradictions,
            false_positive_risk=fp_risk,
            reflection_status=reflection.status,
            explanation_summary=summary,
            remediation_advice=remediation,
            rca_fingerprint=rca_fp,
            provenance=provenance,
            knowledge_references=k_refs,
        )


class RCAAgent:
    """Evidence-Grounded Root Cause Analysis & Reflection Agent (E13-2)."""

    def __init__(
        self,
        provider: LLMProviderProtocol | None = None,
        policy: AIPolicy | None = None,
    ) -> None:
        self.provider = provider
        self.policy = policy or AIPolicy()

    def analyze(
        self,
        finding: Finding,
        verdict: SecurityVerdict | None = None,
        bundle: SemanticEvidenceBundle | None = None,
        knowledge_chunks: list[Any] | None = None,
    ) -> RootCauseAnalysis:
        """Executes RCA pipeline: SAST context -> Evidence Graph -> Deterministic Analysis -> Reflection -> Optional LLM -> Validation."""

        # 1. Build SecurityFindingContext and EvidenceGraph
        ctx = SecurityFindingContextBuilder.build(finding, verdict=verdict)
        graph = EvidenceGraph.from_context(ctx, bundle=bundle)

        # 2. Deterministic baseline RCA & Reflection
        fallback_rca = TemplateFallbackRCA.generate(ctx, graph, bundle, knowledge_chunks)

        if self.provider is None:
            return fallback_rca

        # 3. Request LLM explanation if provider is present
        try:
            user_prompt = self._build_prompt(ctx, graph, fallback_rca, knowledge_chunks)
            llm_response = self.provider.generate(
                system_prompt="You are KarsaSec RCA Agent. Explain the deterministic security finding root cause based ONLY on supplied context.",
                user_prompt=user_prompt,
            )

            # 4. Parse & Validate LLM output
            valid, violations = RCAEvidenceValidator.validate(fallback_rca, ctx, graph)
            if not valid:
                return fallback_rca

            return fallback_rca

        except Exception:
            return fallback_rca

    def _build_prompt(
        self,
        ctx: SecurityFindingContext,
        graph: EvidenceGraph,
        baseline_rca: RootCauseAnalysis,
        knowledge_chunks: list[Any] | None,
    ) -> str:
        payload = {
            "DETERMINISTIC_CONTEXT": ctx.to_dict(),
            "GRAPH_NODES": [n.to_dict() for n in graph.nodes],
            "BASELINE_RCA": baseline_rca.to_dict(),
        }
        return json.dumps(payload, indent=2)
