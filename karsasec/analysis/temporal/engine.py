"""Core Temporal & State Consistency Violation Engine (Batch D2)."""

from __future__ import annotations

import hashlib
from typing import Any

from karsasec.analysis.invariants.models import InvariantViolation
from karsasec.analysis.temporal.models import (
    TemporalConfidence,
    TemporalEvidence,
    TemporalSeverity,
    TemporalViolation,
    TemporalViolationCategory,
)


class TemporalConsistencyEngine:
    """Temporal & State Consistency Violation Engine enforcing INV-D2-01 through INV-D2-15.

    Operating Mode: Pure logical static temporal reasoning layer.
    Strictly forbids: network requests, subprocess, shell, SQL, cloud API calls.
    """

    def evaluate_temporal_consistency(
        self,
        evidence: TemporalEvidence | None = None,
        d1_violations: list[InvariantViolation] | None = None,
        findings: list[dict[str, Any]] | None = None,
    ) -> list[TemporalViolation]:
        """Evaluates temporal evidence against 15 formal temporal invariants."""
        violations: list[TemporalViolation] = []

        if evidence:
            cat = evidence.category

            # 1. INV-D2-01 & Case D/E: Privilege Revocation Consistency
            if cat == TemporalViolationCategory.REVOCATION_DRIFT_VIOLATION:
                if evidence.cache_invalidated or evidence.proof_present:
                    pass  # Case D: Safe
                elif not evidence.cache_invalidated and evidence.events and len(evidence.events) >= 2:
                    # Case E: Role revoked, capability remains active
                    violations.append(
                        self._create_violation(
                            category=cat,
                            severity=TemporalSeverity.CRITICAL,
                            confidence=TemporalConfidence.HIGH,
                            resolution="VULNERABLE",
                            root_causes=("PRIVILEGE_REVOCATION_DRIFT",),
                            evidence_chain=tuple(e.event_id for e in evidence.events),
                            temporal_path=tuple(f"{e.actor}:{e.action}:{e.capability}" for e in evidence.events),
                            affected_resource=evidence.events[0].resource if evidence.events else None,
                        )
                    )
                else:
                    violations.append(
                        self._create_violation(
                            category=cat,
                            severity=TemporalSeverity.UNKNOWN,
                            confidence=TemporalConfidence.UNKNOWN,
                            resolution="UNKNOWN",
                            root_causes=("UNRESOLVED_REVOCATION_RELATIONSHIP",),
                            evidence_chain=(evidence.evidence_id,),
                            temporal_path=("UNRESOLVED",),
                        )
                    )

            # 2. INV-D2-02 & Case A/B/C: TOCTOU Consistency
            elif cat == TemporalViolationCategory.TOCTOU_VIOLATION:
                if evidence.lock_present or evidence.transaction_boundary_present or evidence.proof_present:
                    pass  # Case A: Safe
                elif any(e.action == "CONCURRENT_MUTATION" for e in evidence.events):
                    # Case C: Concurrent mutation without lock => VULNERABLE
                    violations.append(
                        self._create_violation(
                            category=cat,
                            severity=TemporalSeverity.HIGH,
                            confidence=TemporalConfidence.HIGH,
                            resolution="VULNERABLE",
                            root_causes=("NON_ATOMIC_CHECK_USE",),
                            evidence_chain=tuple(e.event_id for e in evidence.events),
                            temporal_path=tuple(f"{e.action}" for e in evidence.events),
                            affected_resource=evidence.events[0].resource if evidence.events else None,
                        )
                    )
                else:
                    # Case B: check -> use without concurrency/lock evidence => UNKNOWN
                    violations.append(
                        self._create_violation(
                            category=cat,
                            severity=TemporalSeverity.UNKNOWN,
                            confidence=TemporalConfidence.UNKNOWN,
                            resolution="UNKNOWN",
                            root_causes=("UNVERIFIED_CONCURRENCY_GAP",),
                            evidence_chain=(evidence.evidence_id,),
                            temporal_path=("CHECK_TO_USE_GAP",),
                        )
                    )

            # 3. INV-D2-03: State Desynchronization
            elif cat == TemporalViolationCategory.STATE_DESYNC_VIOLATION:
                if not evidence.proof_present:
                    violations.append(
                        self._create_violation(
                            category=cat,
                            severity=TemporalSeverity.HIGH,
                            confidence=TemporalConfidence.HIGH,
                            resolution="VULNERABLE",
                            root_causes=("SECURITY_STATE_DESYNCHRONIZATION",),
                            evidence_chain=(evidence.evidence_id,),
                            temporal_path=("CLIENT_SERVER_STATE_MISMATCH",),
                        )
                    )

            # 4. INV-D2-04: Cache Authorization Drift
            elif cat == TemporalViolationCategory.CACHE_AUTHORIZATION_DRIFT:
                if not evidence.cache_invalidated and not evidence.proof_present:
                    violations.append(
                        self._create_violation(
                            category=cat,
                            severity=TemporalSeverity.HIGH,
                            confidence=TemporalConfidence.HIGH,
                            resolution="VULNERABLE",
                            root_causes=("CACHE_INVALIDATION_MISSING",),
                            evidence_chain=(evidence.evidence_id,),
                            temporal_path=("DB_MUTATION_CACHE_STALE",),
                        )
                    )

            # 5. INV-D2-05: Workflow Integrity
            elif cat == TemporalViolationCategory.WORKFLOW_BYPASS_VIOLATION:
                if not evidence.proof_present:
                    violations.append(
                        self._create_violation(
                            category=cat,
                            severity=TemporalSeverity.CRITICAL,
                            confidence=TemporalConfidence.HIGH,
                            resolution="VULNERABLE",
                            root_causes=("REQUIRED_WORKFLOW_STEP_SKIPPED",),
                            evidence_chain=(evidence.evidence_id,),
                            temporal_path=("REQUEST_DIRECT_TO_PAY",),
                        )
                    )

            # 6. INV-D2-06: Race Condition Reachability
            elif cat == TemporalViolationCategory.RACE_CONDITION_REACHABILITY:
                if not evidence.lock_present and not evidence.proof_present:
                    violations.append(
                        self._create_violation(
                            category=cat,
                            severity=TemporalSeverity.HIGH,
                            confidence=TemporalConfidence.HIGH,
                            resolution="VULNERABLE",
                            root_causes=("UNSYNCHRONIZED_SHARED_MUTATION",),
                            evidence_chain=(evidence.evidence_id,),
                            temporal_path=("CONCURRENT_READ_MUTATE",),
                        )
                    )

            # 7. INV-D2-07: Transactional Invariant Failure
            elif cat == TemporalViolationCategory.TRANSACTIONAL_INVARIANT_FAILURE:
                if not evidence.transaction_boundary_present and not evidence.proof_present:
                    violations.append(
                        self._create_violation(
                            category=cat,
                            severity=TemporalSeverity.HIGH,
                            confidence=TemporalConfidence.HIGH,
                            resolution="VULNERABLE",
                            root_causes=("PARTIAL_FAIL_MISSING_ROLLBACK",),
                            evidence_chain=(evidence.evidence_id,),
                            temporal_path=("DEBIT_SUCCESS_CREDIT_FAIL",),
                        )
                    )

            # 8. INV-D2-11: Temporal Authorization
            elif cat == TemporalViolationCategory.TEMPORAL_AUTHORIZATION_VIOLATION:
                if not evidence.proof_present:
                    violations.append(
                        self._create_violation(
                            category=cat,
                            severity=TemporalSeverity.HIGH,
                            confidence=TemporalConfidence.HIGH,
                            resolution="VULNERABLE",
                            root_causes=("STALE_AUTHORIZATION_CONTEXT",),
                            evidence_chain=(evidence.evidence_id,),
                            temporal_path=("AUTH_AT_ISSUANCE_NOT_AT_USE",),
                        )
                    )

            # 9. INV-D2-12: Capability Lifetime Abuse
            elif cat == TemporalViolationCategory.CAPABILITY_LIFETIME_ABUSE:
                if not evidence.proof_present:
                    violations.append(
                        self._create_violation(
                            category=cat,
                            severity=TemporalSeverity.HIGH,
                            confidence=TemporalConfidence.HIGH,
                            resolution="VULNERABLE",
                            root_causes=("REVOKED_CAPABILITY_REACTIVATED",),
                            evidence_chain=(evidence.evidence_id,),
                            temporal_path=("REVOKED_TO_ACTIVE",),
                        )
                    )

            # 10. INV-D2-13: Replay Resistance
            elif cat == TemporalViolationCategory.REPLAY_ATTACK_VIOLATION:
                if not evidence.proof_present:
                    violations.append(
                        self._create_violation(
                            category=cat,
                            severity=TemporalSeverity.HIGH,
                            confidence=TemporalConfidence.HIGH,
                            resolution="VULNERABLE",
                            root_causes=("MISSING_SINGLE_USE_NONCE",),
                            evidence_chain=(evidence.evidence_id,),
                            temporal_path=("REPLAY_SENSITIVE_MUTATION",),
                        )
                    )

            # 11. INV-D2-14: Temporal Tenant Isolation
            elif cat == TemporalViolationCategory.TEMPORAL_TENANT_ISOLATION_VIOLATION:
                if not evidence.proof_present:
                    violations.append(
                        self._create_violation(
                            category=cat,
                            severity=TemporalSeverity.CRITICAL,
                            confidence=TemporalConfidence.HIGH,
                            resolution="VULNERABLE",
                            root_causes=("TENANT_CONTEXT_DRIFT",),
                            evidence_chain=(evidence.evidence_id,),
                            temporal_path=("TENANT_A_SWITCHES_TO_TENANT_B",),
                        )
                    )

            # 12. INV-D2-15: State Monotonicity Violation
            elif cat == TemporalViolationCategory.STATE_MONOTONICITY_VIOLATION:
                if not evidence.proof_present:
                    violations.append(
                        self._create_violation(
                            category=cat,
                            severity=TemporalSeverity.MEDIUM,
                            confidence=TemporalConfidence.HIGH,
                            resolution="VULNERABLE",
                            root_causes=("SECURITY_STATE_DEGRADATION",),
                            evidence_chain=(evidence.evidence_id,),
                            temporal_path=("REVOKED_BACK_TO_ACTIVE",),
                        )
                    )

            # 13. Default UNKNOWN propagation
            elif cat == TemporalViolationCategory.UNKNOWN_TEMPORAL_VIOLATION:
                violations.append(
                    self._create_violation(
                        category=cat,
                        severity=TemporalSeverity.UNKNOWN,
                        confidence=TemporalConfidence.UNKNOWN,
                        resolution="UNKNOWN",
                        root_causes=("AMBIGUOUS_TEMPORAL_TRACE",),
                        evidence_chain=(evidence.evidence_id,),
                        temporal_path=("UNRESOLVED_TEMPORAL_SEQUENCE",),
                    )
                )

        # Integration with D1 Violations (Section 20)
        if d1_violations:
            for d1_v in d1_violations:
                if d1_v.category == "AUTHORITY_VIOLATION" and d1_v.resolution == "VULNERABLE":
                    violations.append(
                        self._create_violation(
                            category=TemporalViolationCategory.TEMPORAL_AUTHORIZATION_VIOLATION,
                            severity=TemporalSeverity.HIGH,
                            confidence=TemporalConfidence.HIGH,
                            resolution="VULNERABLE",
                            root_causes=d1_v.root_cause_chain,
                            evidence_chain=d1_v.evidence_chain,
                            temporal_path=("CORRELATED_D1_AUTHORITY_VIOLATION",),
                            affected_resource=d1_v.affected_boundary,
                        )
                    )
                elif d1_v.category == "RESOURCE_OWNERSHIP_VIOLATION" and d1_v.resolution == "VULNERABLE":
                    violations.append(
                        self._create_violation(
                            category=TemporalViolationCategory.TEMPORAL_TENANT_ISOLATION_VIOLATION,
                            severity=TemporalSeverity.CRITICAL,
                            confidence=TemporalConfidence.HIGH,
                            resolution="VULNERABLE",
                            root_causes=d1_v.root_cause_chain,
                            evidence_chain=d1_v.evidence_chain,
                            temporal_path=("CORRELATED_D1_OWNERSHIP_VIOLATION",),
                            affected_resource=d1_v.affected_boundary,
                        )
                    )

        # Generic findings
        if findings:
            for f in findings:
                res = f.get("resolution", "UNKNOWN")
                if res == "UNKNOWN":
                    violations.append(
                        self._create_violation(
                            category=TemporalViolationCategory.UNKNOWN_TEMPORAL_VIOLATION,
                            severity=TemporalSeverity.UNKNOWN,
                            confidence=TemporalConfidence.UNKNOWN,
                            resolution="UNKNOWN",
                            root_causes=(f.get("rule_id", "UNKNOWN"),),
                            evidence_chain=tuple(f.get("evidence", ["UNKNOWN"])),
                            temporal_path=("UNKNOWN_TRACE",),
                        )
                    )
                elif res == "VULNERABLE":
                    cat_name = f.get("category", "TEMPORAL_AUTHORIZATION_VIOLATION")
                    cat_enum = TemporalViolationCategory(cat_name) if cat_name in TemporalViolationCategory.__members__ else TemporalViolationCategory.TEMPORAL_AUTHORIZATION_VIOLATION
                    violations.append(
                        self._create_violation(
                            category=cat_enum,
                            severity=TemporalSeverity.HIGH,
                            confidence=TemporalConfidence.HIGH,
                            resolution="VULNERABLE",
                            root_causes=(f.get("rule_id", "VULNERABLE"),),
                            evidence_chain=tuple(f.get("evidence", ["EVIDENCE_PRESENT"])),
                            temporal_path=("TEMPORAL_TRACE",),
                        )
                    )

        # Canonical deterministic sorting (INV-D2-08 & Section 9)
        sorted_violations = sorted(
            violations,
            key=lambda v: (
                v.category.value,
                v.severity.value,
                v.resolution,
                v.affected_resource or "",
                v.violation_id,
            ),
        )

        return sorted_violations

    def _create_violation(
        self,
        category: TemporalViolationCategory,
        severity: TemporalSeverity,
        confidence: TemporalConfidence,
        resolution: str,
        root_causes: tuple[str, ...],
        evidence_chain: tuple[str, ...],
        temporal_path: tuple[str, ...],
        affected_resource: str | None = None,
    ) -> TemporalViolation:
        """Constructs an immutable TemporalViolation with canonical SHA256 violation_id."""
        raw_sig = f"{category.value}:{severity.value}:{confidence.value}:{resolution}:{','.join(sorted(root_causes))}:{','.join(sorted(evidence_chain))}:{','.join(sorted(temporal_path))}:{affected_resource or ''}"
        violation_id = f"TEMP_VIOLATION_{hashlib.sha256(raw_sig.encode('utf-8')).hexdigest()[:12].upper()}"

        return TemporalViolation(
            violation_id=violation_id,
            category=category,
            severity=severity,
            confidence=confidence,
            resolution=resolution,
            root_cause_chain=tuple(sorted(root_causes)),
            evidence_chain=tuple(sorted(evidence_chain)),
            temporal_path=tuple(sorted(temporal_path)),
            affected_resource=affected_resource,
        )
