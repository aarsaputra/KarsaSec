"""RCA Domain Models for KarsaSec AI Engine (E13-2).

Enforces Security Invariants G16-G30:
  - G16: SAST Authority Preservation (SecurityVerdict status is NEVER mutated by FP risk or RCA).
  - G17: Evidence-Bounded Reasoning (Every claim is backed by SAST evidence or RAG chunks).
  - G18: UNKNOWN != SAFE (UNKNOWN and NOT_PROVEN states can NEVER be reported as SAFE).
  - G19: Contradiction Transparency (Report CONTRADICTORY_EVIDENCE explicitly).
  - G20-G22: SSA, CallContext, and Branch Polarity Isolation.
  - G26: Deterministic canonical SHA-256 fingerprinting.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import hashlib
from typing import Any

from karsasec.ai.models import ExplanationProvenance, KnowledgeReference


class RootCauseCategory(StrEnum):
    """Categorical classification of root cause mechanism in security findings."""

    DIRECT_USER_INPUT = "DIRECT_USER_INPUT"
    UNSAFE_ASSIGNMENT = "UNSAFE_ASSIGNMENT"
    MISSING_VALIDATION = "MISSING_VALIDATION"
    MISSING_SANITIZATION = "MISSING_SANITIZATION"
    INCOMPATIBLE_SANITIZATION = "INCOMPATIBLE_SANITIZATION"
    UNSAFE_TRANSFORMATION = "UNSAFE_TRANSFORMATION"
    INTERPROCEDURAL_PROPAGATION = "INTERPROCEDURAL_PROPAGATION"
    CROSS_FILE_PROPAGATION = "CROSS_FILE_PROPAGATION"
    CONTROL_FLOW_GUARD_FAILURE = "CONTROL_FLOW_GUARD_FAILURE"
    RETURN_PATH_MIXING = "RETURN_PATH_MIXING"
    SSA_REASSIGNMENT = "SSA_REASSIGNMENT"
    UNKNOWN_ROOT_CAUSE = "UNKNOWN_ROOT_CAUSE"
    CONTRADICTORY_EVIDENCE = "CONTRADICTORY_EVIDENCE"


class FalsePositiveAssessment(StrEnum):
    """Evidence-based False-Positive Risk Rating.

    NOTE: Analytical quality assessment only. NEVER alters SecurityVerdict.status (G16/G18).
    """

    LOW_RISK = "LOW_RISK"
    MEDIUM_RISK = "MEDIUM_RISK"
    HIGH_RISK = "HIGH_RISK"
    NOT_PROVEN = "NOT_PROVEN"


class ReflectionStatus(StrEnum):
    """Four-valued status for evidence completeness and contradiction reflection."""

    PROVEN = "PROVEN"
    NOT_PROVEN = "NOT_PROVEN"
    UNKNOWN = "UNKNOWN"
    CONTRADICTORY = "CONTRADICTORY"


@dataclass(frozen=True, slots=True)
class RootCauseStep:
    """Immutable single step in the root cause evidence chain."""

    step_id: str
    node_id: str
    evidence_kind: str
    file_path: str
    line_number: int
    statement: str
    variable_name: str
    variable_version: str
    call_context: str
    branch_polarity: str
    proof_status: str
    description: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "node_id": self.node_id,
            "evidence_kind": self.evidence_kind,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "statement": self.statement,
            "variable_name": self.variable_name,
            "variable_version": self.variable_version,
            "call_context": self.call_context,
            "branch_polarity": self.branch_polarity,
            "proof_status": self.proof_status,
            "description": self.description,
        }


@dataclass(frozen=True, slots=True)
class EvidenceGap:
    """Immutable representation of missing or unproven evidence along a dataflow path."""

    gap_id: str
    missing_type: str
    description: str
    location: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "gap_id": self.gap_id,
            "missing_type": self.missing_type,
            "description": self.description,
            "location": self.location,
        }


@dataclass(frozen=True, slots=True)
class Contradiction:
    """Immutable representation of conflicting or inconsistent evidence steps."""

    contradiction_id: str
    description: str
    conflicting_nodes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "contradiction_id": self.contradiction_id,
            "description": self.description,
            "conflicting_nodes": list(self.conflicting_nodes),
        }


@dataclass(frozen=True, slots=True)
class EvidenceReflection:
    """Aggregated reflection analysis result on evidence completeness and integrity."""

    status: ReflectionStatus
    gaps: tuple[EvidenceGap, ...] = ()
    contradictions: tuple[Contradiction, ...] = ()
    continuity_proven: bool = False
    unresolved_calls: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": str(self.status),
            "gaps": [g.to_dict() for g in self.gaps],
            "contradictions": [c.to_dict() for c in self.contradictions],
            "continuity_proven": self.continuity_proven,
            "unresolved_calls": list(self.unresolved_calls),
        }


@dataclass(frozen=True, slots=True)
class RootCauseAnalysis:
    """Immutable structured Root Cause Analysis result."""

    finding_id: str
    rule_id: str
    verdict_status: str
    root_cause_category: RootCauseCategory
    primary_cause_step: RootCauseStep | None
    evidence_chain: tuple[RootCauseStep, ...]
    evidence_gaps: tuple[EvidenceGap, ...]
    contradictions: tuple[Contradiction, ...]
    false_positive_risk: FalsePositiveAssessment
    reflection_status: ReflectionStatus
    explanation_summary: str
    remediation_advice: str
    rca_fingerprint: str
    provenance: ExplanationProvenance | None = None
    knowledge_references: tuple[KnowledgeReference, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "verdict_status": self.verdict_status,
            "root_cause_category": str(self.root_cause_category),
            "primary_cause_step": self.primary_cause_step.to_dict() if self.primary_cause_step else None,
            "evidence_chain": [s.to_dict() for s in self.evidence_chain],
            "evidence_gaps": [g.to_dict() for g in self.evidence_gaps],
            "contradictions": [c.to_dict() for c in self.contradictions],
            "false_positive_risk": str(self.false_positive_risk),
            "reflection_status": str(self.reflection_status),
            "explanation_summary": self.explanation_summary,
            "remediation_advice": self.remediation_advice,
            "rca_fingerprint": self.rca_fingerprint,
        }

    @staticmethod
    def compute_fingerprint(
        finding_id: str,
        category: RootCauseCategory,
        chain: tuple[RootCauseStep, ...],
        reflection: ReflectionStatus,
        fp_risk: FalsePositiveAssessment,
    ) -> str:
        """Compute canonical, byte-for-byte deterministic SHA-256 fingerprint."""
        chain_fps = "|".join(s.node_id for s in chain)
        raw = f"{finding_id}|{category.value}|{chain_fps}|{reflection.value}|{fp_risk.value}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()
