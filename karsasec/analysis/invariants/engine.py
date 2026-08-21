"""Core Security Invariant Violation Engine (Batch D1)."""

from __future__ import annotations

import hashlib
from typing import Any

from karsasec.analysis.attack_graph.models import AttackGraph
from karsasec.analysis.breach_simulation.models import BreachScenario, SimulationStatus
from karsasec.analysis.invariants.models import (
    InvariantEvidence,
    InvariantType,
    InvariantViolation,
    ViolationConfidence,
    ViolationSeverity,
)
from karsasec.analysis.privilege.models import PrivilegeEvidence


class SecurityInvariantEngine:
    """Security Invariant Violation Engine enforcing INV-D1-01 through INV-D1-18.

    Operating Mode: Pure logical, read-only static reasoning engine.
    Strictly forbids: network requests, subprocess, shell, SQL, cloud API calls.
    """

    def evaluate_invariants(
        self,
        attack_graph: AttackGraph | None = None,
        privilege_evidence: PrivilegeEvidence | None = None,
        breach_scenario: BreachScenario | None = None,
        evidence_item: InvariantEvidence | None = None,
        findings: list[dict[str, Any]] | None = None,
    ) -> list[InvariantViolation]:
        """Evaluates input evidence against 18 formal security invariants (INV-D1-01 to INV-D1-18)."""
        violations: list[InvariantViolation] = []

        # 1. Rule 1 & INV-D1-04: Trust Boundary
        if evidence_item and evidence_item.invariant_type == InvariantType.TRUST_BOUNDARY:
            if not evidence_item.proof_present:
                violations.append(
                    self._create_violation(
                        category="TRUST_BOUNDARY_VIOLATION",
                        severity=ViolationSeverity.HIGH,
                        confidence=ViolationConfidence.HIGH,
                        root_causes=(evidence_item.source_boundary,),
                        evidence_chain=evidence_item.evidence_path or (evidence_item.source_boundary, evidence_item.target_boundary),
                        boundary=evidence_item.target_boundary,
                        resolution="VULNERABLE",
                    )
                )

        # 2. Rule 2 & INV-D1-05: Privilege Boundary
        if privilege_evidence:
            if privilege_evidence.resolution == "UNKNOWN":
                violations.append(
                    self._create_violation(
                        category="UNKNOWN_INVARIANT",
                        severity=ViolationSeverity.UNKNOWN,
                        confidence=ViolationConfidence.UNKNOWN,
                        root_causes=(privilege_evidence.transition_trigger,),
                        evidence_chain=tuple(privilege_evidence.evidence_path),
                        boundary=privilege_evidence.authorization_boundary,
                        resolution="UNKNOWN",
                    )
                )
            elif privilege_evidence.resolution == "VULNERABLE":
                is_boundary_crossed = privilege_evidence.initial_privilege != privilege_evidence.resulting_privilege
                cat = "PRIVILEGE_BOUNDARY_VIOLATION" if is_boundary_crossed else "AUTHORITY_VIOLATION"
                violations.append(
                    self._create_violation(
                        category=cat,
                        severity=ViolationSeverity.CRITICAL if is_boundary_crossed else ViolationSeverity.HIGH,
                        confidence=ViolationConfidence.HIGH,
                        root_causes=(privilege_evidence.transition_trigger,),
                        evidence_chain=tuple(privilege_evidence.evidence_path or [privilege_evidence.initial_identity, privilege_evidence.resulting_identity]),
                        boundary=privilege_evidence.authorization_boundary,
                        resolution="VULNERABLE",
                    )
                )

        if evidence_item and evidence_item.invariant_type == InvariantType.PRIVILEGE_BOUNDARY:
            if not evidence_item.proof_present:
                violations.append(
                    self._create_violation(
                        category="PRIVILEGE_BOUNDARY_VIOLATION",
                        severity=ViolationSeverity.CRITICAL,
                        confidence=ViolationConfidence.HIGH,
                        root_causes=("PRIVILEGE_ESCALATION",),
                        evidence_chain=evidence_item.evidence_path or ("USER", "ADMIN"),
                        boundary=evidence_item.target_boundary,
                        resolution="VULNERABLE",
                    )
                )

        # 3. Rule 3 & INV-D1-06: Capability Leakage
        if attack_graph:
            caps = set(attack_graph.capabilities)
            is_vuln = attack_graph.to_dict().get("resolution") == "VULNERABLE"
            if is_vuln and ("ROOT_ACCESS" in caps or "CLOUD_ADMIN_ACCESS" in caps or "BULK_DELETE" in caps or "AWS_KEY_EXPOSURE" in caps or "METADATA_ACCESS" in caps):
                violations.append(
                    self._create_violation(
                        category="CAPABILITY_LEAK",
                        severity=ViolationSeverity.CRITICAL,
                        confidence=ViolationConfidence.HIGH,
                        root_causes=tuple(attack_graph.root_causes),
                        evidence_chain=tuple(attack_graph.capabilities + attack_graph.impacts),
                        boundary="CAPABILITY_OWNERSHIP",
                        resolution="VULNERABLE",
                    )
                )

        # 4. Rule 4 & INV-D1-07: State Machine Violation
        if evidence_item and evidence_item.invariant_type == InvariantType.STATE_TRANSITION:
            if evidence_item.initial_state == "UNAUTHENTICATED" and evidence_item.resulting_state == "PRIVILEGED":
                if not evidence_item.proof_present:
                    violations.append(
                        self._create_violation(
                            category="STATE_MACHINE_VIOLATION",
                            severity=ViolationSeverity.HIGH,
                            confidence=ViolationConfidence.HIGH,
                            root_causes=("UNAUTHENTICATED_JUMP",),
                            evidence_chain=evidence_item.evidence_path or ("UNAUTHENTICATED", "PRIVILEGED"),
                            boundary="STATE_MACHINE",
                            resolution="VULNERABLE",
                        )
                    )

        # 5. Rule 5 & INV-D1-05/INV-D1-12: Tenant Isolation
        if breach_scenario:
            if breach_scenario.resolution == SimulationStatus.UNKNOWN:
                violations.append(
                    self._create_violation(
                        category="UNKNOWN_INVARIANT",
                        severity=ViolationSeverity.UNKNOWN,
                        confidence=ViolationConfidence.UNKNOWN,
                        root_causes=breach_scenario.root_causes,
                        evidence_chain=breach_scenario.evidence_path,
                        boundary="UNKNOWN_BOUNDARY",
                        resolution="UNKNOWN",
                    )
                )
            elif breach_scenario.resolution == SimulationStatus.VULNERABLE:
                if "TENANT_BOUNDARY_ESCAPE" in breach_scenario.capabilities or "TENANT_WIPE" in breach_scenario.impacts:
                    violations.append(
                        self._create_violation(
                            category="TENANT_ISOLATION_FAILURE",
                            severity=ViolationSeverity.CRITICAL,
                            confidence=ViolationConfidence.HIGH,
                            root_causes=breach_scenario.root_causes,
                            evidence_chain=breach_scenario.evidence_path,
                            boundary="TENANT_ISOLATION",
                            resolution="VULNERABLE",
                        )
                    )

        # 6. Rule 6 & INV-D1-11: Authority Invariant
        if evidence_item and evidence_item.invariant_type == InvariantType.AUTHORITY:
            if not evidence_item.proof_present:
                violations.append(
                    self._create_violation(
                        category="AUTHORITY_VIOLATION",
                        severity=ViolationSeverity.HIGH,
                        confidence=ViolationConfidence.HIGH,
                        root_causes=("UNVERIFIED_STATE_CHANGE",),
                        evidence_chain=evidence_item.evidence_path or ("USER", "ADMIN_ACTION"),
                        boundary=evidence_item.target_boundary,
                        resolution="VULNERABLE",
                    )
                )

        # 7. Rule 7 & INV-D1-12: Resource Ownership Invariant
        if evidence_item and evidence_item.invariant_type == InvariantType.RESOURCE_OWNERSHIP:
            if not evidence_item.proof_present:
                violations.append(
                    self._create_violation(
                        category="RESOURCE_OWNERSHIP_VIOLATION",
                        severity=ViolationSeverity.HIGH,
                        confidence=ViolationConfidence.HIGH,
                        root_causes=("DIRECT_OBJECT_ACCESS",),
                        evidence_chain=evidence_item.evidence_path or ("DIRECT_GET", "RESOURCE_ID"),
                        boundary="RESOURCE_OWNERSHIP",
                        resolution="VULNERABLE",
                    )
                )

        # 8. Rule 8 & INV-D1-13: Delegation Chain Invariant
        if evidence_item and evidence_item.invariant_type == InvariantType.DELEGATION:
            if not evidence_item.proof_present:
                violations.append(
                    self._create_violation(
                        category="DELEGATION_CHAIN_VIOLATION",
                        severity=ViolationSeverity.HIGH,
                        confidence=ViolationConfidence.HIGH,
                        root_causes=("BROKEN_DELEGATION_CHAIN",),
                        evidence_chain=evidence_item.evidence_path or ("USER", "SERVICE_ACCOUNT"),
                        boundary="DELEGATION",
                        resolution="VULNERABLE",
                    )
                )

        # 9. Rule 9 & INV-D1-14: Lifecycle Invariant
        if evidence_item and evidence_item.invariant_type == InvariantType.LIFECYCLE:
            if not evidence_item.proof_present:
                violations.append(
                    self._create_violation(
                        category="LIFECYCLE_INVARIANT_VIOLATION",
                        severity=ViolationSeverity.HIGH,
                        confidence=ViolationConfidence.HIGH,
                        root_causes=("TOKEN_REUSE_NO_EXPIRATION",),
                        evidence_chain=evidence_item.evidence_path or ("TOKEN_GEN", "TOKEN_REUSE"),
                        boundary="LIFECYCLE",
                        resolution="VULNERABLE",
                    )
                )

        # 10. Rule 10 & INV-D1-15: Consistency Invariant
        if evidence_item and evidence_item.invariant_type == InvariantType.CONSISTENCY:
            if not evidence_item.proof_present:
                violations.append(
                    self._create_violation(
                        category="CONSISTENCY_INVARIANT_VIOLATION",
                        severity=ViolationSeverity.MEDIUM,
                        confidence=ViolationConfidence.HIGH,
                        root_causes=("FRONTEND_BACKEND_MISMATCH",),
                        evidence_chain=evidence_item.evidence_path or ("GATEWAY_ALLOW", "BACKEND_ALLOW"),
                        boundary="CONSISTENCY",
                        resolution="VULNERABLE",
                    )
                )

        # 11. Rule 11 & INV-D1-16: Security Property Reachability Violation
        if breach_scenario and breach_scenario.resolution == SimulationStatus.VULNERABLE:
            sec_props = {"ACCOUNT_TAKEOVER", "TENANT_ESCAPE", "ROOT_ACCESS", "CLOUD_ADMIN", "DATA_EXFILTRATION", "DESTRUCTIVE_ACTION", "SECRET_EXPOSURE"}
            all_found = set(breach_scenario.capabilities).union(set(breach_scenario.impacts))
            matched_props = sec_props.intersection(all_found)
            if matched_props:
                violations.append(
                    self._create_violation(
                        category="REACHABILITY_VIOLATION",
                        severity=ViolationSeverity.CRITICAL,
                        confidence=ViolationConfidence.HIGH,
                        root_causes=breach_scenario.root_causes,
                        evidence_chain=breach_scenario.evidence_path,
                        boundary="SECURITY_PROPERTY_REACHABILITY",
                        resolution="VULNERABLE",
                    )
                )

        # 12. Rule 12 & INV-D1-17: Separation of Duty
        if evidence_item and evidence_item.invariant_type == InvariantType.SEPARATION_OF_DUTY:
            if not evidence_item.proof_present:
                violations.append(
                    self._create_violation(
                        category="SEPARATION_OF_DUTY_VIOLATION",
                        severity=ViolationSeverity.CRITICAL,
                        confidence=ViolationConfidence.HIGH,
                        root_causes=("SINGLE_IDENTITY_DUAL_ACTION",),
                        evidence_chain=evidence_item.evidence_path or ("CREATE_PAYMENT", "APPROVE_PAYMENT"),
                        boundary="SEPARATION_OF_DUTY",
                        resolution="VULNERABLE",
                    )
                )

        # 13. Rule 13 & INV-D1-18: Defense-in-Depth
        if evidence_item and evidence_item.invariant_type == InvariantType.DEFENSE_IN_DEPTH:
            if not evidence_item.proof_present:
                violations.append(
                    self._create_violation(
                        category="DEFENSE_IN_DEPTH_VIOLATION",
                        severity=ViolationSeverity.MEDIUM,
                        confidence=ViolationConfidence.HIGH,
                        root_causes=("MISSING_DOWNSTREAM_ENFORCEMENT",),
                        evidence_chain=evidence_item.evidence_path or ("AUTHN_PRESENT", "AUTHZ_MISSING"),
                        boundary="DEFENSE_IN_DEPTH",
                        resolution="VULNERABLE",
                    )
                )

        # 14. Findings list processing
        if findings:
            for f in findings:
                res = f.get("resolution", "UNKNOWN")
                if res == "UNKNOWN":
                    violations.append(
                        self._create_violation(
                            category="UNKNOWN_INVARIANT",
                            severity=ViolationSeverity.UNKNOWN,
                            confidence=ViolationConfidence.UNKNOWN,
                            root_causes=(f.get("rule_id", "UNKNOWN"),),
                            evidence_chain=tuple(f.get("evidence", ["UNKNOWN"])),
                            boundary=f.get("boundary", "UNKNOWN_BOUNDARY"),
                            resolution="UNKNOWN",
                        )
                    )
                elif res == "VULNERABLE":
                    cat = f.get("category", "TRUST_BOUNDARY_VIOLATION")
                    violations.append(
                        self._create_violation(
                            category=cat,
                            severity=ViolationSeverity.HIGH,
                            confidence=ViolationConfidence.HIGH,
                            root_causes=(f.get("rule_id", "VULNERABLE"),),
                            evidence_chain=tuple(f.get("evidence", ["EVIDENCE_PRESENT"])),
                            boundary=f.get("boundary", "DEFAULT_BOUNDARY"),
                            resolution="VULNERABLE",
                        )
                    )

        # Deterministic Canonical Sorting (INV-D1-08 & INV-D1-09)
        sorted_violations = sorted(violations, key=lambda v: (v.category, v.severity.value, v.affected_boundary, v.violation_id))
        return sorted_violations

    def _create_violation(
        self,
        category: str,
        severity: ViolationSeverity,
        confidence: ViolationConfidence,
        root_causes: tuple[str, ...],
        evidence_chain: tuple[str, ...],
        boundary: str,
        resolution: str,
    ) -> InvariantViolation:
        """Constructs an immutable InvariantViolation with canonical SHA256 violation_id."""
        raw_sig = f"{category}:{severity}:{confidence}:{','.join(sorted(root_causes))}:{','.join(sorted(evidence_chain))}:{boundary}:{resolution}"
        violation_id = f"VIOLATION_{hashlib.sha256(raw_sig.encode('utf-8')).hexdigest()[:12].upper()}"

        return InvariantViolation(
            violation_id=violation_id,
            category=category,
            severity=severity,
            confidence=confidence,
            root_cause_chain=tuple(sorted(root_causes)),
            evidence_chain=tuple(sorted(evidence_chain)),
            affected_boundary=boundary,
            resolution=resolution,
        )
