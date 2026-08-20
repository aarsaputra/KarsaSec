"""Security Verdict Domain Models for Sprint E12-18.

Defines immutable, deterministic domain models representing evidence-backed security decisions:
  - VerdictStatus (VULNERABLE, SAFE, UNKNOWN, NOT_PROVEN)
  - DecisionReason (Machine-readable reason codes)
  - VerdictConfidence (HIGH, MEDIUM, LOW)
  - EvidenceReference (Traceable reference to originating evidence)
  - SecurityVerdict (Immutable evidence-backed verdict with SHA256 fingerprints)

Invariants:
  - G1: UNKNOWN is NEVER SAFE. Incomplete evidence preserves UNKNOWN/NOT_PROVEN.
  - G8: Byte-for-byte deterministic fingerprinting stable across PYTHONHASHSEED=1..5.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class VerdictStatus(StrEnum):
    """Deterministic status of a security verdict."""

    VULNERABLE = "VULNERABLE"
    SAFE = "SAFE"
    UNKNOWN = "UNKNOWN"
    NOT_PROVEN = "NOT_PROVEN"


class DecisionReason(StrEnum):
    """Machine-readable decision reason codes."""

    TAINT_REACHES_SINK = "TAINT_REACHES_SINK"
    SANITIZER_COMPATIBLE = "SANITIZER_COMPATIBLE"
    SANITIZER_INCOMPATIBLE = "SANITIZER_INCOMPATIBLE"
    GUARD_PROVEN = "GUARD_PROVEN"
    GUARD_NOT_PROVEN = "GUARD_NOT_PROVEN"
    TRANSFORMATION_PROVEN = "TRANSFORMATION_PROVEN"
    TRANSFORMATION_NOT_PROVEN = "TRANSFORMATION_NOT_PROVEN"
    REASSIGNMENT_INVALIDATED = "REASSIGNMENT_INVALIDATED"
    SINK_COMPATIBILITY_PROVEN = "SINK_COMPATIBILITY_PROVEN"
    SINK_COMPATIBILITY_NOT_PROVEN = "SINK_COMPATIBILITY_NOT_PROVEN"
    SOURCE_PROVENANCE = "SOURCE_PROVENANCE"
    CALL_CONTEXT_ISOLATED = "CALL_CONTEXT_ISOLATED"
    SSA_VERSION_ISOLATED = "SSA_VERSION_ISOLATED"
    PATH_CONSTRAINT_PROVEN = "PATH_CONSTRAINT_PROVEN"
    PATH_CONSTRAINT_NOT_PROVEN = "PATH_CONSTRAINT_NOT_PROVEN"
    UNKNOWN_EVIDENCE = "UNKNOWN_EVIDENCE"
    NON_CONVERGED_ANALYSIS = "NON_CONVERGED_ANALYSIS"


class VerdictConfidence(StrEnum):
    """Confidence rating for the security verdict."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True)
class EvidenceReference:
    """Traceable reference pointing to an originating piece of semantic evidence."""

    evidence_id: str
    evidence_kind: str
    source_node: str = ""
    sink_node: str = ""
    file_path: str = ""
    line_number: int = 0
    var_version: str = ""
    call_context_id: str = ""
    branch_polarity: str = ""
    proof_status: str = ""
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "evidence_kind": self.evidence_kind,
            "source_node": self.source_node,
            "sink_node": self.sink_node,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "var_version": self.var_version,
            "call_context_id": self.call_context_id,
            "branch_polarity": self.branch_polarity,
            "proof_status": self.proof_status,
            "description": self.description,
        }


def compute_evidence_fingerprint(
    rule_id: str,
    sink_category: str,
    file_path: str,
    function_name: str,
    line_number: int,
    var_version: str,
    call_context: str | None,
    branch_polarity: str,
    source_ids: tuple[str, ...],
    provenance_path: tuple[str, ...],
    reason_codes: tuple[DecisionReason, ...],
    evidences: tuple[EvidenceReference, ...],
) -> str:
    """Computes a canonical, deterministic SHA-256 fingerprint over security-relevant evidence.

    Independent of dict order or PYTHONHASHSEED randomization.
    """
    sorted_sources = sorted(source_ids)
    sorted_prov = list(provenance_path)
    sorted_reasons = sorted(str(r) for r in reason_codes)
    sorted_ev_ids = sorted(ev.evidence_id for ev in evidences)
    norm_file = file_path.replace("\\", "/").strip().lower()

    raw_components = [
        f"rule:{rule_id.strip()}",
        f"category:{sink_category.strip().upper()}",
        f"file:{norm_file}",
        f"func:{function_name.strip()}",
        f"line:{line_number}",
        f"var_version:{var_version.strip()}",
        f"call_context:{str(call_context or '').strip()}",
        f"branch_polarity:{branch_polarity.strip()}",
        f"sources:{','.join(sorted_sources)}",
        f"prov:{'->'.join(sorted_prov)}",
        f"reasons:{','.join(sorted_reasons)}",
        f"ev_ids:{','.join(sorted_ev_ids)}",
    ]
    raw_str = "|".join(raw_components)
    return hashlib.sha256(raw_str.encode("utf-8")).hexdigest()[:32]


@dataclass(frozen=True)
class SecurityVerdict:
    """Immutable evidence-backed security decision (E12-18).

    Binds analysis conclusions to exact evidence references and provenance paths.
    """

    verdict_id: str
    status: VerdictStatus
    confidence: VerdictConfidence
    rule_id: str
    sink_id: str
    sink_category: str
    file_path: str
    function_name: str
    line_number: int
    variable_version: str
    call_context: str | None
    branch_polarity: str
    reason_codes: tuple[DecisionReason, ...]
    source_ids: tuple[str, ...]
    provenance_path: tuple[str, ...]
    evidence_references: tuple[EvidenceReference, ...]
    compatibility_decision: str | None
    matching_constraint: str | None
    evidence_fingerprint: str
    canonical_fingerprint: str

    @classmethod
    def create(
        cls,
        status: VerdictStatus,
        confidence: VerdictConfidence,
        rule_id: str,
        sink_id: str,
        sink_category: str,
        file_path: str,
        function_name: str,
        line_number: int,
        variable_version: str = "",
        call_context: str | None = None,
        branch_polarity: str = "",
        reason_codes: tuple[DecisionReason, ...] | list[DecisionReason] = (),
        source_ids: tuple[str, ...] | list[str] = (),
        provenance_path: tuple[str, ...] | list[str] = (),
        evidence_references: tuple[EvidenceReference, ...] | list[EvidenceReference] = (),
        compatibility_decision: str | None = None,
        matching_constraint: str | None = None,
    ) -> SecurityVerdict:
        tuple_reasons = tuple(reason_codes)
        tuple_sources = tuple(source_ids)
        tuple_prov = tuple(provenance_path)
        tuple_ev = tuple(evidence_references)

        ev_fp = compute_evidence_fingerprint(
            rule_id=rule_id,
            sink_category=sink_category,
            file_path=file_path,
            function_name=function_name,
            line_number=line_number,
            var_version=variable_version,
            call_context=call_context,
            branch_polarity=branch_polarity,
            source_ids=tuple_sources,
            provenance_path=tuple_prov,
            reason_codes=tuple_reasons,
            evidences=tuple_ev,
        )

        canonical_raw = f"{status.value}|{ev_fp}|{compatibility_decision or 'NONE'}"
        canon_fp = hashlib.sha256(canonical_raw.encode("utf-8")).hexdigest()[:32]
        verdict_id = f"verdict_{canon_fp[:16]}"

        return cls(
            verdict_id=verdict_id,
            status=status,
            confidence=confidence,
            rule_id=rule_id,
            sink_id=sink_id,
            sink_category=sink_category,
            file_path=file_path,
            function_name=function_name,
            line_number=line_number,
            variable_version=variable_version,
            call_context=call_context,
            branch_polarity=branch_polarity,
            reason_codes=tuple_reasons,
            source_ids=tuple_sources,
            provenance_path=tuple_prov,
            evidence_references=tuple_ev,
            compatibility_decision=compatibility_decision,
            matching_constraint=matching_constraint,
            evidence_fingerprint=ev_fp,
            canonical_fingerprint=canon_fp,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict_id": self.verdict_id,
            "status": self.status.value,
            "confidence": self.confidence.value,
            "rule_id": self.rule_id,
            "sink_id": self.sink_id,
            "sink_category": self.sink_category,
            "file_path": self.file_path,
            "function_name": self.function_name,
            "line_number": self.line_number,
            "variable_version": self.variable_version,
            "call_context": self.call_context,
            "branch_polarity": self.branch_polarity,
            "reason_codes": [r.value for r in self.reason_codes],
            "source_ids": list(self.source_ids),
            "provenance_path": list(self.provenance_path),
            "evidence_references": [ev.to_dict() for ev in self.evidence_references],
            "compatibility_decision": self.compatibility_decision,
            "matching_constraint": self.matching_constraint,
            "evidence_fingerprint": self.evidence_fingerprint,
            "canonical_fingerprint": self.canonical_fingerprint,
        }
