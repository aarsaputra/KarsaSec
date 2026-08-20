"""Security Decision Engine for Sprint E12-18.

Implements SecurityDecisionEngine which accepts a SemanticEvidenceBundle and an authoritative
SinkCompatibilityMatrix evaluation result to construct an immutable SecurityVerdict.

Architectural Authority:
  - E12-13 SinkCompatibilityMatrix remains the sole final authority for sink safety.
  - SecurityDecisionEngine acts as a decision assembler and provenance binder.
  - Invariant G1: UNKNOWN is NEVER SAFE. Incomplete evidence preserves UNKNOWN/VULNERABLE.
  - Invariant G2: SecurityDecisionEngine MUST NOT independently declare sink safety without matrix proof.
"""

from __future__ import annotations

from karsasec.graph.dataflow.semantic_evidence import EvidenceKind, ProofStatus, SemanticEvidenceBundle
from karsasec.graph.dataflow.security_verdict import (
    DecisionReason,
    EvidenceReference,
    SecurityVerdict,
    VerdictConfidence,
    VerdictStatus,
)
from karsasec.graph.dataflow.sink_matrix import CompatibilityDecision, EvaluationResult, sink_compatibility_matrix


class SecurityDecisionEngine:
    """Evidence-backed security verdict assembly engine (E12-18)."""

    def evaluate_verdict(
        self,
        bundle: SemanticEvidenceBundle,
        rule_id: str = "KS-SECURITY-0001",
        file_path: str = "",
        function_name: str = "",
        line_number: int = 0,
        variable_version: str = "",
        call_context: str | None = None,
        branch_polarity: str = "",
    ) -> SecurityVerdict:
        """Evaluates a SemanticEvidenceBundle and constructs a SecurityVerdict preserving all invariants."""
        # 1. Convert bundle evidences into EvidenceReference domain objects
        ev_refs: list[EvidenceReference] = []
        for ev in bundle.evidences:
            ref = EvidenceReference(
                evidence_id=ev.node_id,
                evidence_kind=ev.evidence_kind.value
                if isinstance(ev.evidence_kind, EvidenceKind)
                else str(ev.evidence_kind),
                source_node=bundle.sink_node_id,
                sink_node=bundle.sink_node_id,
                file_path=ev.file_path or file_path,
                line_number=line_number,
                var_version=ev.var_version or variable_version,
                call_context_id=str(ev.call_context or call_context or ""),
                branch_polarity=ev.branch_polarity or branch_polarity,
                proof_status=ev.proof_status.value
                if isinstance(ev.proof_status, ProofStatus)
                else str(ev.proof_status),
                description=ev.description,
            )
            ev_refs.append(ref)

        reasons: list[DecisionReason] = []
        source_ids: list[str] = []
        prov_path: list[str] = []

        # Extract sources and provenance path from evidences
        for ev in bundle.evidences:
            if ev.evidence_kind == EvidenceKind.SOURCE and ev.var_name:
                source_ids.append(ev.var_name)
            for hop in ev.provenance_path:
                if hop and hop not in prov_path:
                    prov_path.append(hop)

        # 2. Query SinkCompatibilityMatrix authority if not pre-evaluated
        matrix_eval: EvaluationResult | None = bundle.evaluation_result
        if matrix_eval is None and bundle.sink_category:
            matrix_eval = sink_compatibility_matrix.evaluate(
                bundle.aggregated_constraints,
                bundle.sink_category,
                bundle.sink_context,
            )

        compat_decision_str = matrix_eval.decision.value if matrix_eval else None
        matching_constraint_str = (
            matrix_eval.matching_constraint.value if matrix_eval and matrix_eval.matching_constraint else None
        )

        # 3. Apply Decision Logic under Security Invariants G1 & G2
        # Invariant G1 & G2: SAFE is only permitted when PROVEN and Matrix decision is COMPATIBLE
        if (
            bundle.proof_status == ProofStatus.PROVEN
            and matrix_eval
            and matrix_eval.decision == CompatibilityDecision.COMPATIBLE
        ):
            status = VerdictStatus.SAFE
            confidence = VerdictConfidence.HIGH
            reasons.append(DecisionReason.SINK_COMPATIBILITY_PROVEN)

            # Determine specific proof reason
            for ev in bundle.evidences:
                if ev.evidence_kind == EvidenceKind.GUARD:
                    reasons.append(DecisionReason.GUARD_PROVEN)
                elif ev.evidence_kind == EvidenceKind.SANITIZER:
                    reasons.append(DecisionReason.SANITIZER_COMPATIBLE)
                elif ev.evidence_kind == EvidenceKind.TRANSFORMATION:
                    reasons.append(DecisionReason.TRANSFORMATION_PROVEN)

            if not any(
                r in reasons
                for r in (
                    DecisionReason.GUARD_PROVEN,
                    DecisionReason.SANITIZER_COMPATIBLE,
                    DecisionReason.TRANSFORMATION_PROVEN,
                )
            ):
                reasons.append(DecisionReason.PATH_CONSTRAINT_PROVEN)

        elif matrix_eval and matrix_eval.decision in (CompatibilityDecision.NOT_PROVEN, CompatibilityDecision.CONFLICT):
            if bundle.proof_status == ProofStatus.PROVEN:
                # Evidence is proven but incompatible with sink context => VULNERABLE
                status = VerdictStatus.VULNERABLE
                confidence = VerdictConfidence.HIGH
                reasons.append(DecisionReason.TAINT_REACHES_SINK)
                reasons.append(DecisionReason.SANITIZER_INCOMPATIBLE)
                reasons.append(DecisionReason.SINK_COMPATIBILITY_NOT_PROVEN)
            else:
                status = VerdictStatus.UNKNOWN
                confidence = VerdictConfidence.LOW
                reasons.append(DecisionReason.UNKNOWN_EVIDENCE)
                reasons.append(DecisionReason.GUARD_NOT_PROVEN)
                reasons.append(DecisionReason.SINK_COMPATIBILITY_NOT_PROVEN)

        elif bundle.proof_status == ProofStatus.NOT_PROVEN:
            status = VerdictStatus.UNKNOWN
            confidence = VerdictConfidence.LOW
            reasons.append(DecisionReason.UNKNOWN_EVIDENCE)
            reasons.append(DecisionReason.GUARD_NOT_PROVEN)
            reasons.append(DecisionReason.SINK_COMPATIBILITY_NOT_PROVEN)

        else:
            # Fallback for unknown / incomplete evidence: UNKNOWN (never SAFE!)
            status = VerdictStatus.UNKNOWN
            confidence = VerdictConfidence.MEDIUM
            reasons.append(DecisionReason.UNKNOWN_EVIDENCE)
            reasons.append(DecisionReason.PATH_CONSTRAINT_NOT_PROVEN)

        # Context isolation reason tracking
        if call_context:
            reasons.append(DecisionReason.CALL_CONTEXT_ISOLATED)
        if variable_version:
            reasons.append(DecisionReason.SSA_VERSION_ISOLATED)

        # Deduplicate reasons preserving order
        dedup_reasons: list[DecisionReason] = []
        for r in reasons:
            if r not in dedup_reasons:
                dedup_reasons.append(r)

        return SecurityVerdict.create(
            status=status,
            confidence=confidence,
            rule_id=rule_id,
            sink_id=bundle.sink_node_id,
            sink_category=bundle.sink_category,
            file_path=file_path,
            function_name=function_name,
            line_number=line_number,
            variable_version=variable_version,
            call_context=call_context,
            branch_polarity=branch_polarity,
            reason_codes=dedup_reasons,
            source_ids=source_ids,
            provenance_path=prov_path,
            evidence_references=ev_refs,
            compatibility_decision=compat_decision_str,
            matching_constraint=matching_constraint_str,
        )
