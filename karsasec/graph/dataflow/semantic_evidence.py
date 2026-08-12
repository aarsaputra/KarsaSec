"""Semantic Evidence Model for KarsaSec (E12-17).

Design Principles & Invariants:
  - First-class evidence taxonomy distinguishing GUARD, TRANSFORMATION, SANITIZER, ASSIGNMENT, SOURCE, RETURN, CALL_SITE, CROSS_FILE, SINK.
  - Immutable frozen dataclasses with canonical tuple and frozenset collections.
  - Byte-for-byte deterministic fingerprinting across Python execution sessions.
  - Strict preservation of SSA variable versions ($x#1 vs $x#2) and CallContext identities.
  - Anti-hardcoding: Pure semantic dataflow evidence model. Zero benchmark or rule strings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import hashlib
import json

from karsasec.graph.dataflow.abstract_state import SemanticConstraint, TaintState
from karsasec.graph.dataflow.provenance import CallContext
from karsasec.graph.dataflow.sink_matrix import EvaluationResult, SinkContext


class EvidenceKind(StrEnum):
    """Categorical classification of semantic evidence steps."""
    SOURCE = "SOURCE"
    ASSIGNMENT = "ASSIGNMENT"
    GUARD = "GUARD"
    TRANSFORMATION = "TRANSFORMATION"
    SANITIZER = "SANITIZER"
    RETURN = "RETURN"
    CALL_SITE = "CALL_SITE"
    CROSS_FILE = "CROSS_FILE"
    SINK = "SINK"


class ProofStatus(StrEnum):
    """Four-valued security proof status."""
    PROVEN = "PROVEN"
    NOT_PROVEN = "NOT_PROVEN"
    UNKNOWN = "UNKNOWN"
    NON_CONVERGED = "NON_CONVERGED"


@dataclass(frozen=True, slots=True)
class SemanticEvidence:
    """Immutable single step of semantic evidence in a dataflow provenance chain."""
    node_id: str
    evidence_kind: EvidenceKind
    file_path: str = ""
    function_name: str = ""
    statement: str = ""
    var_name: str = ""
    var_version: str = ""
    taint_state: TaintState = TaintState.UNKNOWN
    type_constraints: frozenset[SemanticConstraint] = field(default_factory=frozenset)
    sanitization_constraints: frozenset[SemanticConstraint] = field(default_factory=frozenset)
    normalization_constraints: frozenset[SemanticConstraint] = field(default_factory=frozenset)
    call_context: CallContext | None = None
    branch_polarity: str = ""
    provenance_path: tuple[str, ...] = ()
    proof_status: ProofStatus = ProofStatus.UNKNOWN
    source_location: str = ""
    description: str = ""

    @property
    def all_constraints(self) -> frozenset[SemanticConstraint]:
        """Combine all constraint types into a single frozen set."""
        return self.type_constraints | self.sanitization_constraints | self.normalization_constraints

    def semantic_fingerprint(self) -> str:
        """Compute a canonical SHA256 fingerprint for this evidence item."""
        call_ctx_str = f"{self.call_context.call_site_id}::{self.call_context.caller_function}->{self.call_context.callee_function}" if self.call_context else ""
        canonical_dict = {
            "node_id": self.node_id,
            "evidence_kind": str(self.evidence_kind),
            "file_path": self.file_path,
            "function_name": self.function_name,
            "statement": self.statement,
            "var_name": self.var_name,
            "var_version": self.var_version,
            "taint_state": str(getattr(self.taint_state, "value", self.taint_state)),
            "constraints": sorted(str(c) for c in self.all_constraints),
            "call_context": call_ctx_str,
            "branch_polarity": self.branch_polarity,
            "provenance_path": list(self.provenance_path),
            "proof_status": str(self.proof_status),
            "source_location": self.source_location,
            "description": self.description,
        }
        encoded = json.dumps(canonical_dict, sort_keys=True).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class SemanticEvidenceBundle:
    """Canonical aggregated collection of semantic evidence for a sink evaluation."""
    sink_node_id: str
    sink_category: str
    sink_context: SinkContext = SinkContext.UNKNOWN
    evidences: tuple[SemanticEvidence, ...] = ()
    aggregated_constraints: frozenset[SemanticConstraint] = field(default_factory=frozenset)
    proof_status: ProofStatus = ProofStatus.UNKNOWN
    evaluation_result: EvaluationResult | None = None

    def semantic_fingerprint(self) -> str:
        """Compute a canonical SHA256 fingerprint for this entire evidence bundle."""
        ev_fps = [ev.semantic_fingerprint() for ev in self.evidences]
        eval_res_str = f"{self.evaluation_result.decision}:{self.evaluation_result.reason}" if self.evaluation_result else ""
        canonical_dict = {
            "sink_node_id": self.sink_node_id,
            "sink_category": self.sink_category,
            "sink_context": str(self.sink_context),
            "evidences": ev_fps,
            "aggregated_constraints": sorted(str(c) for c in self.aggregated_constraints),
            "proof_status": str(self.proof_status),
            "evaluation_result": eval_res_str,
        }
        encoded = json.dumps(canonical_dict, sort_keys=True).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()
