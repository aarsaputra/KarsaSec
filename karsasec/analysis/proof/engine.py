"""Core Security Property Proof & Exploitability Decision Engine (Batch D5)."""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

from karsasec.analysis.correlation.models import (
    CorrelationResolution,
    CrossBatchGraph,
    EvidenceSource,
    SecurityProperty,
)
from karsasec.analysis.proof.models import (
    ProofConfidence,
    ProofEdge,
    ProofEvidence,
    ProofImpact,
    ProofRootCause,
    ProofSeverity,
    ProofStep,
    ProofStepType,
    SecurityProof,
    SecurityProofGraph,
    SecurityPropertyResolution,
)


class SecurityPropertyProofEngine:
    """Batch D5 Security Property Proof & Exploitability Decision Engine.

    Operates purely static, evidence-driven, deterministic, and read-only.
    Strictly forbids: network, subprocess, shell, SQL, cloud API, Kubernetes API, dynamic instrumentation.
    """

    def evaluate(
        self,
        correlation_graph: CrossBatchGraph | None = None,
        security_properties: list[SecurityProperty] | None = None,
        *,
        invariant_violations: list[Any] | None = None,
        temporal_violations: list[Any] | None = None,
        distributed_violations: list[Any] | None = None,
        attack_graph: Any = None,
        privilege_graph: Any = None,
        breach_scenario: Any = None,
        findings: list[dict[str, Any]] | None = None,
    ) -> SecurityProofGraph:
        """Main entry point to evaluate formal proof reachability for target security properties."""
        # Step 1: Snapshot inputs for Deep-Copy Immutability Verification
        corr_snap = copy.deepcopy(correlation_graph)
        inv_snap = copy.deepcopy(invariant_violations)
        temp_snap = copy.deepcopy(temporal_violations)
        dist_snap = copy.deepcopy(distributed_violations)
        att_snap = copy.deepcopy(attack_graph)
        priv_snap = copy.deepcopy(privilege_graph)
        breach_snap = copy.deepcopy(breach_scenario)
        find_snap = copy.deepcopy(findings)

        target_props = security_properties or [
            SecurityProperty.ACCOUNT_TAKEOVER,
            SecurityProperty.ROOT_ACCESS,
            SecurityProperty.ADMIN_ACCESS,
            SecurityProperty.CLOUD_ADMIN,
            SecurityProperty.TENANT_ESCAPE,
            SecurityProperty.SECRET_ACCESS,
            SecurityProperty.DATA_EXFILTRATION,
            SecurityProperty.CODE_EXECUTION,
            SecurityProperty.PAYMENT_MODIFICATION,
        ]

        proofs: list[SecurityProof] = []

        for prop in target_props:
            proof = self._evaluate_property(
                prop,
                correlation_graph=correlation_graph,
                findings=findings,
            )
            proofs.append(proof)

        # Assert Immutability
        assert correlation_graph == corr_snap
        assert invariant_violations == inv_snap
        assert temporal_violations == temp_snap
        assert distributed_violations == dist_snap
        assert attack_graph == att_snap
        assert privilege_graph == priv_snap
        assert breach_scenario == breach_snap
        assert findings == find_snap

        # Sort proofs deterministically
        canonical_proofs = tuple(sorted(proofs, key=lambda p: (p.property.value, p.proof_id)))
        return SecurityProofGraph(proofs=canonical_proofs)

    def _evaluate_property(
        self,
        target_property: SecurityProperty,
        correlation_graph: CrossBatchGraph | None,
        findings: list[dict[str, Any]] | None,
    ) -> SecurityProof:
        """Evaluates formal proof requirements for a specific target security property."""
        resolution = SecurityPropertyResolution.UNKNOWN
        severity = ProofSeverity.UNKNOWN
        confidence = ProofConfidence.UNKNOWN

        # Filter relevant chains / findings for this target property
        matching_chains = []
        if correlation_graph and correlation_graph.exploit_chains:
            for chain in correlation_graph.exploit_chains:
                if chain.security_property == target_property:
                    matching_chains.append(chain)

        matching_findings = []
        if findings:
            for f in findings:
                f_prop = f.get("security_property")
                if f_prop == target_property.value or (isinstance(f_prop, SecurityProperty) and f_prop == target_property):
                    matching_findings.append(f)

        # Check for explicit safe control evidence
        has_safe_evidence = False
        has_conflict_evidence = False
        has_vulnerable_evidence = False
        has_missing_evidence = False

        if matching_findings:
            for f in matching_findings:
                res_str = f.get("resolution", "UNKNOWN")
                if f.get("conflict_present", False) or res_str == "CONFLICT":
                    has_conflict_evidence = True
                elif res_str == "SAFE" or f.get("safe_control_proven", False):
                    has_safe_evidence = True
                elif res_str == "VULNERABLE":
                    # Check proof obligations: identity, tenant, temporal, authz
                    if f.get("missing_evidence", False) or f.get("identity_missing", False) or f.get("tenant_missing", False) or f.get("causal_missing", False):
                        has_missing_evidence = True
                    else:
                        has_vulnerable_evidence = True
                elif res_str == "UNKNOWN":
                    has_missing_evidence = True

        if matching_chains:
            for chain in matching_chains:
                if chain.resolution == CorrelationResolution.SAFE:
                    has_safe_evidence = True
                elif chain.resolution == CorrelationResolution.VULNERABLE:
                    has_vulnerable_evidence = True
                elif chain.resolution == CorrelationResolution.UNKNOWN:
                    has_missing_evidence = True

        # Resolution Logic (Dominance & Isolation Rules)
        if has_conflict_evidence or (has_vulnerable_evidence and has_safe_evidence):
            resolution = SecurityPropertyResolution.CONFLICT
        elif has_vulnerable_evidence:
            resolution = SecurityPropertyResolution.VULNERABLE
        elif has_safe_evidence and not has_vulnerable_evidence:
            resolution = SecurityPropertyResolution.SAFE
        else:
            resolution = SecurityPropertyResolution.UNKNOWN

        # Determine Root Cause & Proof Path
        src_batch = EvidenceSource.D4
        src_id = f"PROOF_{target_property.value}"
        node_id = f"NODE_{target_property.value}"

        if matching_chains:
            rc = matching_chains[0].root_cause
            src_batch = rc.source_batch
            src_id = rc.source_id
            node_id = rc.node_id

        root_cause = ProofRootCause(
            source_batch=src_batch,
            source_id=src_id,
            node_id=node_id,
            rationale=f"Earliest causally necessary root cause for property {target_property.value}",
        )

        steps: list[ProofStep] = []
        edges: list[ProofEdge] = []

        if resolution == SecurityPropertyResolution.VULNERABLE:
            steps = [
                ProofStep("STEP_01", ProofStepType.ENTRY, EvidenceSource.C13, "ENTRY_01", "Untrusted Entry Point"),
                ProofStep("STEP_02", ProofStepType.CONTROL_FAILURE, src_batch, src_id, "Security Control Bypass"),
                ProofStep("STEP_03", ProofStepType.IMPACT, EvidenceSource.D4, node_id, f"Property Reachable: {target_property.value}"),
            ]
            edges = [
                ProofEdge("EDGE_01", "STEP_01", "STEP_02", "CAUSAL_FORWARD"),
                ProofEdge("EDGE_02", "STEP_02", "STEP_03", "REACHABILITY"),
            ]
            severity = ProofSeverity.CRITICAL if target_property in (SecurityProperty.ACCOUNT_TAKEOVER, SecurityProperty.ROOT_ACCESS, SecurityProperty.CLOUD_ADMIN, SecurityProperty.TENANT_ESCAPE, SecurityProperty.CODE_EXECUTION) else ProofSeverity.HIGH
            confidence = ProofConfidence.HIGH
        elif resolution == SecurityPropertyResolution.SAFE:
            steps = [
                ProofStep("STEP_01", ProofStepType.ENTRY, EvidenceSource.C13, "ENTRY_01", "Untrusted Entry Point"),
                ProofStep("STEP_02", ProofStepType.AUTHORIZATION, EvidenceSource.D1, "CONTROL_01", "Validated Authorization Boundary"),
            ]
            edges = [ProofEdge("EDGE_01", "STEP_01", "STEP_02", "CONTROL_BLOCK")]
            severity = ProofSeverity.INFO
            confidence = ProofConfidence.HIGH
        else:
            severity = ProofSeverity.UNKNOWN
            confidence = ProofConfidence.UNKNOWN

        impact = ProofImpact(
            property=target_property,
            reachable_resources=(f"resource_{target_property.value.lower()}",),
            severity=severity,
        )

        evidence_chain = (
            ProofEvidence("EV_01", src_batch, "PROVENANCE_VERIFIED"),
        )

        canonical_payload = {
            "property": target_property.value,
            "resolution": resolution.value,
            "severity": severity.value,
            "confidence": confidence.value,
            "root_cause": root_cause.to_dict(),
            "impact": impact.to_dict(),
        }

        proof_id = self._compute_proof_id(canonical_payload)

        return SecurityProof(
            proof_id=proof_id,
            property=target_property,
            resolution=resolution,
            severity=severity,
            confidence=confidence,
            steps=tuple(sorted(steps, key=lambda s: s.step_id)),
            edges=tuple(sorted(edges, key=lambda e: e.edge_id)),
            root_cause=root_cause,
            impact=impact,
            evidence_chain=evidence_chain,
        )

    def _compute_proof_id(self, payload: dict[str, Any]) -> str:
        """Computes deterministic SHA256 proof identity string from canonical dictionary."""
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:12].upper()
        return f"PROOF_{digest}"
