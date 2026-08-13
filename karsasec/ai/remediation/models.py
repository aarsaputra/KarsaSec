"""Remediation Domain Models for KarsaSec AI Engine (Sprint E13-3).

Defines immutable, evidence-grounded remediation strategy and patch proposal models.

Enforces Security Invariants G1-G17:
  - G1: UNKNOWN != SAFE (UNKNOWN and NOT_PROVEN states force MANUAL_REVIEW_REQUIRED).
  - G3: SecurityVerdict Immutability (Read-only data; zero status/finding mutation).
  - G5: Evidence Grounding (Every strategy & hunk references exact SAST evidence).
  - G12-G14: Pure Data / No Mutation (DATA ONLY, no file writing/git/subprocess APIs).
  - G15: Human Review Gate (Default status REQUIRES_HUMAN_REVIEW; Patch Proposal — Not Applied).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import hashlib
from typing import Any

from karsasec.ai.models import KnowledgeReference
from karsasec.ai.rca.models import RootCauseCategory


class RemediationStrategyType(StrEnum):
    """Categorical classification of remediation strategy type."""

    ADD_INPUT_VALIDATION = "ADD_INPUT_VALIDATION"
    ADD_OUTPUT_ENCODING = "ADD_OUTPUT_ENCODING"
    REPLACE_UNSAFE_API = "REPLACE_UNSAFE_API"
    ADD_AUTHORIZATION_CHECK = "ADD_AUTHORIZATION_CHECK"
    ADD_PARAMETERIZATION = "ADD_PARAMETERIZATION"
    ADD_CSRF_PROTECTION = "ADD_CSRF_PROTECTION"
    REMOVE_SECRET = "REMOVE_SECRET"
    ADD_SECURITY_HEADER = "ADD_SECURITY_HEADER"
    FIX_INSECURE_CONFIGURATION = "FIX_INSECURE_CONFIGURATION"
    CONSTRAIN_DATA_FLOW = "CONSTRAIN_DATA_FLOW"
    REFACTOR_UNSAFE_TRANSFORMATION = "REFACTOR_UNSAFE_TRANSFORMATION"
    MANUAL_REVIEW_REQUIRED = "MANUAL_REVIEW_REQUIRED"
    UNKNOWN_REMEDIATION = "UNKNOWN_REMEDIATION"


class PatchValidationStatus(StrEnum):
    """Validation status for generated patch proposals."""

    VALID = "VALID"
    INVALID = "INVALID"
    INCOMPLETE = "INCOMPLETE"
    NOT_PROVEN = "NOT_PROVEN"
    REQUIRES_HUMAN_REVIEW = "REQUIRES_HUMAN_REVIEW"


@dataclass(frozen=True, slots=True)
class RemediationStrategy:
    """Immutable structured remediation strategy derived from RCA evidence."""

    finding_id: str
    root_cause_category: RootCauseCategory | str
    strategy_type: RemediationStrategyType
    rationale: str
    target_file: str
    target_locations: tuple[str, ...]
    affected_symbols: tuple[str, ...]
    evidence_references: tuple[str, ...]
    knowledge_references: tuple[KnowledgeReference, ...]
    confidence: float
    assumptions: tuple[str, ...]
    limitations: tuple[str, ...]
    strategy_fingerprint: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "root_cause_category": str(self.root_cause_category),
            "strategy_type": str(self.strategy_type),
            "rationale": self.rationale,
            "target_file": self.target_file,
            "target_locations": list(self.target_locations),
            "affected_symbols": list(self.affected_symbols),
            "evidence_references": list(self.evidence_references),
            "knowledge_references": [
                {
                    "chunk_id": k.chunk_id,
                    "title": k.title,
                    "source": k.source,
                    "relevance_score": k.relevance_score,
                }
                for k in self.knowledge_references
            ],
            "confidence": self.confidence,
            "assumptions": list(self.assumptions),
            "limitations": list(self.limitations),
            "strategy_fingerprint": self.strategy_fingerprint,
        }

    @staticmethod
    def compute_fingerprint(
        finding_id: str,
        category: RootCauseCategory | str,
        strategy_type: RemediationStrategyType,
        target_file: str,
        evidence_refs: tuple[str, ...],
    ) -> str:
        """Compute canonical, byte-for-byte deterministic SHA-256 fingerprint."""
        sorted_ev = "|".join(sorted(evidence_refs))
        norm_target = target_file.replace("\\", "/")
        raw = f"{finding_id}|{str(category)}|{strategy_type.value}|{norm_target}|{sorted_ev}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class PatchHunk:
    """Immutable single diff hunk referencing exact evidence."""

    file_path: str
    start_line: int
    end_line: int
    original_text: str
    proposed_text: str
    context: str
    evidence_reference: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "original_text": self.original_text,
            "proposed_text": self.proposed_text,
            "context": self.context,
            "evidence_reference": self.evidence_reference,
        }


@dataclass(frozen=True, slots=True)
class PatchProposal:
    """Immutable data-only patch proposal object.

    NOTE: Does NOT contain file-writing or subprocess capabilities (G12-G14).
    """

    proposal_id: str
    finding_id: str
    target_files: tuple[str, ...]
    hunks: tuple[PatchHunk, ...]
    unified_diff: str
    rationale: str
    root_cause_reference: str
    evidence_references: tuple[str, ...]
    expected_effect: str
    risk_level: str
    assumptions: tuple[str, ...]
    validation_status: PatchValidationStatus
    proposal_fingerprint: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "finding_id": self.finding_id,
            "target_files": list(self.target_files),
            "hunks": [h.to_dict() for h in self.hunks],
            "unified_diff": self.unified_diff,
            "rationale": self.rationale,
            "root_cause_reference": self.root_cause_reference,
            "evidence_references": list(self.evidence_references),
            "expected_effect": self.expected_effect,
            "risk_level": self.risk_level,
            "assumptions": list(self.assumptions),
            "validation_status": str(self.validation_status),
            "proposal_fingerprint": self.proposal_fingerprint,
        }

    @staticmethod
    def compute_fingerprint(
        finding_id: str,
        target_files: tuple[str, ...],
        unified_diff: str,
        status: PatchValidationStatus,
    ) -> str:
        """Compute canonical, byte-for-byte deterministic SHA-256 fingerprint."""
        sorted_files = "|".join(sorted(f.replace("\\", "/") for f in target_files))
        raw = f"{finding_id}|{sorted_files}|{unified_diff.strip()}|{status.value}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()
