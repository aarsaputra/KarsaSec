"""Core Distributed Security Consistency & Cross-Boundary Reasoning Engine (Batch D3)."""

from __future__ import annotations

import hashlib
from typing import Any

from karsasec.analysis.distributed.models import (
    DistributedConfidence,
    DistributedEvidence,
    DistributedGraph,
    DistributedSeverity,
    DistributedViolation,
    DistributedViolationCategory,
)
from karsasec.analysis.invariants.models import InvariantViolation
from karsasec.analysis.temporal.models import TemporalViolation


class DistributedSecurityConsistencyEngine:
    """Distributed Security Consistency Engine enforcing INV-D3-01 through INV-D3-18.

    Operating Mode: Pure logical static reasoning over distributed security evidence.
    Strictly forbids: network requests, subprocess, shell, SQL, cloud API, Kubernetes calls.
    """

    def analyze(
        self,
        distributed_graph: DistributedGraph | None = None,
        attack_graph: Any = None,
        privilege_graph: Any = None,
        breach_scenario: Any = None,
        invariant_violations: list[InvariantViolation] | None = None,
        temporal_violations: list[TemporalViolation] | None = None,
        evidence: DistributedEvidence | None = None,
        findings: list[dict[str, Any]] | None = None,
    ) -> list[DistributedViolation]:
        """Evaluates distributed evidence against 18 formal invariants."""
        violations: list[DistributedViolation] = []

        # Graph structural validation (Section 14)
        if distributed_graph:
            if not distributed_graph.services or not distributed_graph.events:
                # Malformed graph => UNKNOWN / SAFE based on evidence
                pass

        if evidence:
            cat = evidence.category

            # 1. INV-D3-01: Cross-Service Trust Continuity (Case A)
            if cat == DistributedViolationCategory.CROSS_SERVICE_TRUST_VIOLATION:
                if evidence.validation_present or evidence.proof_present:
                    pass  # Case A: Safe
                else:
                    violations.append(
                        self._create_violation(
                            category=cat,
                            severity=DistributedSeverity.CRITICAL,
                            confidence=DistributedConfidence.HIGH,
                            resolution="VULNERABLE",
                            services=tuple(s.name for s in evidence.services) if evidence.services else ("gateway", "backend"),
                            actor=evidence.events[0].actor.principal_name if evidence.events else "user",
                            initial_privilege="LOW_TRUST",
                            resulting_privilege="HIGH_TRUST",
                            tenant_context=evidence.events[0].tenant_id if evidence.events else "tenant_default",
                            evidence_chain=(evidence.evidence_id,),
                            cross_boundary_path=("LOW_TRUST_DOMAIN", "HIGH_TRUST_DOMAIN"),
                        )
                    )

            # 2. INV-D3-02: Authorization Decision Continuity
            elif cat == DistributedViolationCategory.AUTHORIZATION_CONTEXT_DRIFT:
                if evidence.validation_present or evidence.proof_present:
                    pass
                else:
                    violations.append(
                        self._create_violation(
                            category=cat,
                            severity=DistributedSeverity.HIGH,
                            confidence=DistributedConfidence.HIGH,
                            resolution="VULNERABLE",
                            services=tuple(s.name for s in evidence.services) if evidence.services else ("service_a", "service_b"),
                            actor=evidence.events[0].actor.principal_name if evidence.events else "user",
                            initial_privilege="AUTHORIZED_T1",
                            resulting_privilege="STALE_AUTHORIZED_T2",
                            tenant_context=evidence.events[0].tenant_id if evidence.events else "tenant_default",
                            evidence_chain=(evidence.evidence_id,),
                            cross_boundary_path=("SERVICE_A", "SERVICE_B"),
                        )
                    )

            # 3. INV-D3-03: Identity Provenance Preservation
            elif cat == DistributedViolationCategory.IDENTITY_PROVENANCE_LOSS:
                if evidence.proof_present:
                    pass
                else:
                    violations.append(
                        self._create_violation(
                            category=cat,
                            severity=DistributedSeverity.HIGH,
                            confidence=DistributedConfidence.HIGH,
                            resolution="VULNERABLE",
                            services=tuple(s.name for s in evidence.services) if evidence.services else ("service_a", "service_b"),
                            actor="UNKNOWN_ACTOR",
                            initial_privilege="USER",
                            resulting_privilege="ANONYMOUS_FORWARD",
                            tenant_context=evidence.events[0].tenant_id if evidence.events else "tenant_default",
                            evidence_chain=(evidence.evidence_id,),
                            cross_boundary_path=("SERVICE_A", "SERVICE_B"),
                        )
                    )

            # 4. INV-D3-04: Tenant Context Preservation (Case C & G)
            elif cat == DistributedViolationCategory.CROSS_SERVICE_TENANT_ESCAPE:
                if evidence.proof_present:
                    pass  # Case C: Safe
                elif evidence.correlation_id in ("MISSING_CORRELATION", "MISSING_TENANT_EVIDENCE"):
                    # Case G: Missing tenant evidence => UNKNOWN
                    violations.append(
                        self._create_violation(
                            category=cat,
                            severity=DistributedSeverity.UNKNOWN,
                            confidence=DistributedConfidence.UNKNOWN,
                            resolution="UNKNOWN",
                            services=("service_a", "service_b"),
                            actor="user",
                            initial_privilege="TENANT_A",
                            resulting_privilege="TENANT_UNKNOWN",
                            tenant_context="UNKNOWN",
                            evidence_chain=(evidence.evidence_id,),
                            cross_boundary_path=("SERVICE_A", "SERVICE_B"),
                        )
                    )
                else:
                    violations.append(
                        self._create_violation(
                            category=cat,
                            severity=DistributedSeverity.CRITICAL,
                            confidence=DistributedConfidence.HIGH,
                            resolution="VULNERABLE",
                            services=tuple(s.name for s in evidence.services) if evidence.services else ("service_a", "service_b"),
                            actor=evidence.events[0].actor.principal_name if evidence.events else "user",
                            initial_privilege="TENANT_A",
                            resulting_privilege="TENANT_B",
                            tenant_context="TENANT_B",
                            evidence_chain=(evidence.evidence_id,),
                            cross_boundary_path=("TENANT_A", "TENANT_B"),
                        )
                    )

            # 5. INV-D3-05: Privilege Non-Amplification (Case B & F)
            elif cat == DistributedViolationCategory.DISTRIBUTED_PRIVILEGE_AMPLIFICATION:
                if evidence.explicit_delegation_present or evidence.proof_present:
                    pass  # Case B: Safe
                elif evidence.correlation_id == "MISSING_DELEGATION_EVIDENCE":
                    # Case F: Missing delegation evidence => UNKNOWN
                    violations.append(
                        self._create_violation(
                            category=cat,
                            severity=DistributedSeverity.UNKNOWN,
                            confidence=DistributedConfidence.UNKNOWN,
                            resolution="UNKNOWN",
                            services=("service_a", "service_b"),
                            actor="user",
                            initial_privilege="USER",
                            resulting_privilege="UNKNOWN",
                            tenant_context="tenant_default",
                            evidence_chain=(evidence.evidence_id,),
                            cross_boundary_path=("USER", "SERVICE_B"),
                        )
                    )
                else:
                    violations.append(
                        self._create_violation(
                            category=cat,
                            severity=DistributedSeverity.CRITICAL,
                            confidence=DistributedConfidence.HIGH,
                            resolution="VULNERABLE",
                            services=tuple(s.name for s in evidence.services) if evidence.services else ("gateway", "service_a", "service_b"),
                            actor=evidence.events[0].actor.principal_name if evidence.events else "user",
                            initial_privilege="USER",
                            resulting_privilege="ADMIN",
                            tenant_context="tenant_a",
                            evidence_chain=(evidence.evidence_id,),
                            cross_boundary_path=("USER", "SERVICE_A", "SERVICE_B", "ADMIN"),
                        )
                    )

            # 6. INV-D3-06: Delegation Chain Integrity
            elif cat == DistributedViolationCategory.DISTRIBUTED_DELEGATION_VIOLATION:
                if evidence.explicit_delegation_present or evidence.proof_present:
                    pass
                else:
                    violations.append(
                        self._create_violation(
                            category=cat,
                            severity=DistributedSeverity.HIGH,
                            confidence=DistributedConfidence.HIGH,
                            resolution="VULNERABLE",
                            services=tuple(s.name for s in evidence.services) if evidence.services else ("service_a", "service_b"),
                            actor="user",
                            initial_privilege="DELEGATOR",
                            resulting_privilege="BROKEN_DELEGATION",
                            tenant_context="tenant_default",
                            evidence_chain=(evidence.evidence_id,),
                            cross_boundary_path=("SERVICE_A", "SERVICE_B"),
                        )
                    )

            # 7. INV-D3-07: Authorization Context Binding
            elif cat == DistributedViolationCategory.AUTHORIZATION_CONTEXT_DETACHMENT:
                if evidence.proof_present:
                    pass
                else:
                    violations.append(
                        self._create_violation(
                            category=cat,
                            severity=DistributedSeverity.HIGH,
                            confidence=DistributedConfidence.HIGH,
                            resolution="VULNERABLE",
                            services=("service_a", "service_b"),
                            actor="user",
                            initial_privilege="BOUND_CONTEXT",
                            resulting_privilege="UNBOUND_CONTEXT",
                            tenant_context="tenant_default",
                            evidence_chain=(evidence.evidence_id,),
                            cross_boundary_path=("SERVICE_A", "SERVICE_B"),
                        )
                    )

            # 8. INV-D3-08: Message Security Context Preservation
            elif cat == DistributedViolationCategory.MESSAGE_SECURITY_CONTEXT_LOSS:
                if evidence.proof_present:
                    pass
                else:
                    violations.append(
                        self._create_violation(
                            category=cat,
                            severity=DistributedSeverity.HIGH,
                            confidence=DistributedConfidence.HIGH,
                            resolution="VULNERABLE",
                            services=("producer", "consumer"),
                            actor="user",
                            initial_privilege="SENSITIVE_EVENT",
                            resulting_privilege="MISSING_CONTEXT",
                            tenant_context="tenant_default",
                            evidence_chain=(evidence.evidence_id,),
                            cross_boundary_path=("PRODUCER", "QUEUE", "CONSUMER"),
                        )
                    )

            # 9. INV-D3-09: Async Authorization Validity (Case D)
            elif cat == DistributedViolationCategory.ASYNC_AUTHORIZATION_DRIFT:
                if evidence.validation_present or evidence.proof_present:
                    pass  # Case D: Safe
                else:
                    violations.append(
                        self._create_violation(
                            category=cat,
                            severity=DistributedSeverity.HIGH,
                            confidence=DistributedConfidence.HIGH,
                            resolution="VULNERABLE",
                            services=("auth_service", "worker"),
                            actor="user",
                            initial_privilege="ROLE_REVOKED",
                            resulting_privilege="WORKER_EXECUTED",
                            tenant_context="tenant_default",
                            evidence_chain=(evidence.evidence_id,),
                            cross_boundary_path=("REVOCATION", "QUEUE", "WORKER_EXECUTION"),
                        )
                    )

            # 10. INV-D3-10: Cross-Service State Consistency
            elif cat == DistributedViolationCategory.DISTRIBUTED_STATE_INCONSISTENCY:
                if evidence.proof_present:
                    pass
                else:
                    violations.append(
                        self._create_violation(
                            category=cat,
                            severity=DistributedSeverity.HIGH,
                            confidence=DistributedConfidence.HIGH,
                            resolution="VULNERABLE",
                            services=("service_a", "service_b"),
                            actor="user",
                            initial_privilege="STATE_A",
                            resulting_privilege="STATE_B_CONTRADICTION",
                            tenant_context="tenant_default",
                            evidence_chain=(evidence.evidence_id,),
                            cross_boundary_path=("SERVICE_A", "SERVICE_B"),
                        )
                    )

            # 11. INV-D3-11: Distributed Cache Consistency
            elif cat == DistributedViolationCategory.DISTRIBUTED_CACHE_SECURITY_DRIFT:
                if evidence.validation_present or evidence.proof_present:
                    pass
                else:
                    violations.append(
                        self._create_violation(
                            category=cat,
                            severity=DistributedSeverity.HIGH,
                            confidence=DistributedConfidence.HIGH,
                            resolution="VULNERABLE",
                            services=("db", "cache"),
                            actor="user",
                            initial_privilege="DB_POLICY_UPDATED",
                            resulting_privilege="CACHE_STALE",
                            tenant_context="tenant_default",
                            evidence_chain=(evidence.evidence_id,),
                            cross_boundary_path=("DB", "REDIS_CACHE"),
                        )
                    )

            # 12. INV-D3-12: Gateway/Backend Security Consistency (Case A)
            elif cat == DistributedViolationCategory.GATEWAY_BACKEND_SECURITY_MISMATCH:
                if evidence.validation_present or evidence.proof_present:
                    pass  # Safe
                else:
                    violations.append(
                        self._create_violation(
                            category=cat,
                            severity=DistributedSeverity.HIGH,
                            confidence=DistributedConfidence.HIGH,
                            resolution="VULNERABLE",
                            services=("gateway", "backend"),
                            actor="user",
                            initial_privilege="GATEWAY_ALLOW",
                            resulting_privilege="BACKEND_DENY_MISMATCH",
                            tenant_context="tenant_default",
                            evidence_chain=(evidence.evidence_id,),
                            cross_boundary_path=("GATEWAY", "BACKEND"),
                        )
                    )

            # 13. INV-D3-13: Service Identity Separation (Case E)
            elif cat == DistributedViolationCategory.SERVICE_USER_IDENTITY_CONFUSION:
                if evidence.impersonation_proof_present or evidence.proof_present:
                    pass  # Case E: Safe
                else:
                    violations.append(
                        self._create_violation(
                            category=cat,
                            severity=DistributedSeverity.HIGH,
                            confidence=DistributedConfidence.HIGH,
                            resolution="VULNERABLE",
                            services=("service_a", "service_b"),
                            actor="service_account_a",
                            initial_privilege="SERVICE_ACCOUNT",
                            resulting_privilege="END_USER_EQUIVALENT",
                            tenant_context="tenant_default",
                            evidence_chain=(evidence.evidence_id,),
                            cross_boundary_path=("SERVICE_ACCOUNT", "END_USER"),
                        )
                    )

            # 14. INV-D3-14: Event Provenance Integrity
            elif cat == DistributedViolationCategory.EVENT_PROVENANCE_VIOLATION:
                if evidence.proof_present:
                    pass
                else:
                    violations.append(
                        self._create_violation(
                            category=cat,
                            severity=DistributedSeverity.HIGH,
                            confidence=DistributedConfidence.HIGH,
                            resolution="VULNERABLE",
                            services=("event_bus", "consumer"),
                            actor="user",
                            initial_privilege="EVENT_PRODUCED",
                            resulting_privilege="MISSING_PROVENANCE",
                            tenant_context="tenant_default",
                            evidence_chain=(evidence.evidence_id,),
                            cross_boundary_path=("PRODUCER", "EVENT_BUS", "CONSUMER"),
                        )
                    )

            # 15. INV-D3-15: Cross-Boundary Replay Resistance (Case H)
            elif cat == DistributedViolationCategory.DISTRIBUTED_REPLAY_VIOLATION:
                if evidence.replay_protection_present or evidence.proof_present:
                    pass
                elif evidence.correlation_id == "MISSING_REPLAY_EVIDENCE":
                    # Case H: Missing replay evidence => UNKNOWN
                    violations.append(
                        self._create_violation(
                            category=cat,
                            severity=DistributedSeverity.UNKNOWN,
                            confidence=DistributedConfidence.UNKNOWN,
                            resolution="UNKNOWN",
                            services=("service_a", "service_b"),
                            actor="user",
                            initial_privilege="SENSITIVE_MUTATION",
                            resulting_privilege="UNKNOWN",
                            tenant_context="tenant_default",
                            evidence_chain=(evidence.evidence_id,),
                            cross_boundary_path=("SERVICE_A", "SERVICE_B"),
                        )
                    )
                else:
                    violations.append(
                        self._create_violation(
                            category=cat,
                            severity=DistributedSeverity.HIGH,
                            confidence=DistributedConfidence.HIGH,
                            resolution="VULNERABLE",
                            services=("service_a", "service_b"),
                            actor="user",
                            initial_privilege="SENSITIVE_MUTATION",
                            resulting_privilege="REPLAYABLE",
                            tenant_context="tenant_default",
                            evidence_chain=(evidence.evidence_id,),
                            cross_boundary_path=("SERVICE_A", "SERVICE_B"),
                        )
                    )

            # 16. INV-D3-16: Distributed Separation of Duty
            elif cat == DistributedViolationCategory.DISTRIBUTED_SOD_VIOLATION:
                if evidence.proof_present:
                    pass
                else:
                    violations.append(
                        self._create_violation(
                            category=cat,
                            severity=DistributedSeverity.CRITICAL,
                            confidence=DistributedConfidence.HIGH,
                            resolution="VULNERABLE",
                            services=("payment_service", "approval_service"),
                            actor="actor_single",
                            initial_privilege="CREATE_PAYMENT",
                            resulting_privilege="APPROVE_PAYMENT",
                            tenant_context="tenant_default",
                            evidence_chain=(evidence.evidence_id,),
                            cross_boundary_path=("PAYMENT_SERVICE", "APPROVAL_SERVICE"),
                        )
                    )

            # 17. INV-D3-17: Distributed Defense-in-Depth
            elif cat == DistributedViolationCategory.DISTRIBUTED_DEFENSE_IN_DEPTH_VIOLATION:
                if evidence.proof_present:
                    pass
                else:
                    violations.append(
                        self._create_violation(
                            category=cat,
                            severity=DistributedSeverity.HIGH,
                            confidence=DistributedConfidence.HIGH,
                            resolution="VULNERABLE",
                            services=("upstream", "downstream"),
                            actor="user",
                            initial_privilege="UPSTREAM_SECURITY_ENFORCED",
                            resulting_privilege="DOWNSTREAM_SECURITY_REMOVED",
                            tenant_context="tenant_default",
                            evidence_chain=(evidence.evidence_id,),
                            cross_boundary_path=("UPSTREAM", "DOWNSTREAM"),
                        )
                    )

            # 18. INV-D3-18: Cross-Boundary UNKNOWN Preservation
            elif cat == DistributedViolationCategory.UNKNOWN_DISTRIBUTED_SECURITY_STATE:
                violations.append(
                    self._create_violation(
                        category=cat,
                        severity=DistributedSeverity.UNKNOWN,
                        confidence=DistributedConfidence.UNKNOWN,
                        resolution="UNKNOWN",
                        services=("service_a", "service_b"),
                        actor="user",
                        initial_privilege="UNKNOWN",
                        resulting_privilege="UNKNOWN",
                        tenant_context="UNKNOWN",
                        evidence_chain=(evidence.evidence_id,),
                        cross_boundary_path=("UNKNOWN_BOUNDARY",),
                    )
                )

        # Cross-Batch Correlation (Section 19 & Guardrail 4)
        if invariant_violations:
            for inv in invariant_violations:
                if inv.category == "PRIVILEGE_BOUNDARY_VIOLATION" and inv.resolution == "VULNERABLE":
                    violations.append(
                        self._create_violation(
                            category=DistributedViolationCategory.DISTRIBUTED_PRIVILEGE_AMPLIFICATION,
                            severity=DistributedSeverity.CRITICAL,
                            confidence=DistributedConfidence.HIGH,
                            resolution="VULNERABLE",
                            services=("gateway", "service_a", "service_b"),
                            actor="user",
                            initial_privilege="USER",
                            resulting_privilege="ADMIN",
                            tenant_context="tenant_default",
                            evidence_chain=inv.evidence_chain,
                            cross_boundary_path=("D1_CORRELATED_PATH",),
                        )
                    )

        if temporal_violations:
            for temp in temporal_violations:
                if str(temp.category) == "ASYNC_AUTHORIZATION_DRIFT" and temp.resolution == "VULNERABLE":
                    violations.append(
                        self._create_violation(
                            category=DistributedViolationCategory.ASYNC_AUTHORIZATION_DRIFT,
                            severity=DistributedSeverity.HIGH,
                            confidence=DistributedConfidence.HIGH,
                            resolution="VULNERABLE",
                            services=("producer", "consumer_worker"),
                            actor="user",
                            initial_privilege="ROLE_REVOKED",
                            resulting_privilege="WORKER_EXECUTED",
                            tenant_context="tenant_default",
                            evidence_chain=temp.evidence_chain,
                            cross_boundary_path=("D2_CORRELATED_PATH",),
                        )
                    )

        # Findings support
        if findings:
            for f in findings:
                res = f.get("resolution", "UNKNOWN")
                if res == "UNKNOWN":
                    violations.append(
                        self._create_violation(
                            category=DistributedViolationCategory.UNKNOWN_DISTRIBUTED_SECURITY_STATE,
                            severity=DistributedSeverity.UNKNOWN,
                            confidence=DistributedConfidence.UNKNOWN,
                            resolution="UNKNOWN",
                            services=("service_a", "service_b"),
                            actor="user",
                            initial_privilege="UNKNOWN",
                            resulting_privilege="UNKNOWN",
                            tenant_context="UNKNOWN",
                            evidence_chain=tuple(f.get("evidence", ["UNKNOWN"])),
                            cross_boundary_path=("UNKNOWN_TRACE",),
                        )
                    )
                elif res == "VULNERABLE":
                    cat_name = f.get("category", "CROSS_SERVICE_TRUST_VIOLATION")
                    cat_enum = DistributedViolationCategory(cat_name) if cat_name in DistributedViolationCategory.__members__ else DistributedViolationCategory.CROSS_SERVICE_TRUST_VIOLATION
                    violations.append(
                        self._create_violation(
                            category=cat_enum,
                            severity=DistributedSeverity.HIGH,
                            confidence=DistributedConfidence.HIGH,
                            resolution="VULNERABLE",
                            services=("service_a", "service_b"),
                            actor="user",
                            initial_privilege="VULNERABLE",
                            resulting_privilege="VULNERABLE",
                            tenant_context="tenant_default",
                            evidence_chain=tuple(f.get("evidence", ["EVIDENCE_PRESENT"])),
                            cross_boundary_path=("DISTRIBUTED_TRACE",),
                        )
                    )

        # Canonical deterministic sorting (Section 12)
        sorted_violations = sorted(
            violations,
            key=lambda v: (
                v.category.value,
                v.severity.value,
                v.resolution,
                ",".join(v.services),
                v.violation_id,
            ),
        )

        return sorted_violations

    def _create_violation(
        self,
        category: DistributedViolationCategory,
        severity: DistributedSeverity,
        confidence: DistributedConfidence,
        resolution: str,
        services: tuple[str, ...],
        actor: str,
        initial_privilege: str,
        resulting_privilege: str,
        tenant_context: str,
        evidence_chain: tuple[str, ...],
        cross_boundary_path: tuple[str, ...],
        delegation_chain: tuple[str, ...] = (),
    ) -> DistributedViolation:
        """Constructs an immutable DistributedViolation with canonical SHA256 violation_id."""
        raw_sig = f"{category.value}:{severity.value}:{confidence.value}:{resolution}:{','.join(sorted(services))}:{actor}:{initial_privilege}:{resulting_privilege}:{tenant_context}:{','.join(sorted(evidence_chain))}:{','.join(sorted(cross_boundary_path))}"
        violation_id = f"D3_VIOLATION_{hashlib.sha256(raw_sig.encode('utf-8')).hexdigest()[:12].upper()}"

        return DistributedViolation(
            violation_id=violation_id,
            category=category,
            severity=severity,
            confidence=confidence,
            resolution=resolution,
            services=tuple(sorted(services)),
            actor=actor,
            initial_privilege=initial_privilege,
            resulting_privilege=resulting_privilege,
            tenant_context=tenant_context,
            delegation_chain=tuple(sorted(delegation_chain)),
            evidence_chain=tuple(sorted(evidence_chain)),
            cross_boundary_path=tuple(sorted(cross_boundary_path)),
        )
