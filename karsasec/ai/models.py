"""Pydantic validation models for evidence-grounded AI explanations (E13-1)."""

from __future__ import annotations

import hashlib
from typing import Any

from pydantic import BaseModel, Field


class EvidenceClaim(BaseModel):
    """Structured claim made by the AI model regarding security evidence."""

    claim_type: str = Field(description="Kind of evidence claim: SANITIZER, GUARD, TAINT_PATH, TRANSFORMATION")
    described_entity: str = Field(description="Code symbol or function name referred to")
    is_supported: bool = Field(default=False, description="Whether claim is verified against deterministic SAST evidence")
    evidence_reference: str = Field(default="NONE", description="Reference ID or summary of supporting evidence")


class KnowledgeReference(BaseModel):
    """Reference to retrieved RAG knowledge chunk."""

    chunk_id: str
    title: str
    source: str
    relevance_score: float = 0.0


class ExplanationProvenance(BaseModel):
    """Immutable provenance metadata tracking inputs and execution parameters of AI explanation."""

    finding_id: str
    scan_id: str = "scan_default"
    verdict_fingerprint: str
    evidence_fingerprint: str
    knowledge_fingerprints: list[str] = Field(default_factory=list)
    provider: str = "litellm"
    model: str = "gemini-2.5-flash"
    prompt_version: str = "v1.0"
    schema_version: str = "v1.0"
    canonical_fingerprint: str = ""

    def compute_fingerprint(self) -> str:
        """Computes deterministic SHA-256 canonical explanation fingerprint."""
        sorted_k_fps = "|".join(sorted(self.knowledge_fingerprints))
        raw = f"{self.finding_id}|{self.verdict_fingerprint}|{self.evidence_fingerprint}|{sorted_k_fps}|{self.prompt_version}|{self.schema_version}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


class SecurityExplanation(BaseModel):
    """Validated structured explanation generated for a security finding."""

    finding_id: str
    summary: str
    vulnerability_type: str
    why_vulnerable: str
    source_analysis: str
    sink_analysis: str
    data_flow_explanation: str
    security_impact: str
    guard_analysis: str
    sanitizer_analysis: str
    remediation_guidance: str
    limitations: str
    confidence_score: float = Field(default=1.0, ge=0.0, le=1.0)
    evidence_claims: list[EvidenceClaim] = Field(default_factory=list)
    knowledge_references: list[KnowledgeReference] = Field(default_factory=list)
    provenance: ExplanationProvenance
    explanation_fingerprint: str = ""

    def model_post_init(self, __context: Any) -> None:
        if not self.explanation_fingerprint and self.provenance:
            self.explanation_fingerprint = self.provenance.compute_fingerprint()
