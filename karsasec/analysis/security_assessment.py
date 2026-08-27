"""SecurityAssessment domain model, assessment identity computation, and structured explanation engine for Sprint E13."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from karsasec.analysis.vulnerability_cluster import ClusterStatus

if TYPE_CHECKING:
    from karsasec.analysis.evidence_graph import EvidenceGraph
    from karsasec.analysis.security_finding import SecurityFinding
    from karsasec.analysis.vulnerability_cluster import VulnerabilityCluster


def compute_assessment_id(
    cluster_id: str,
    vulnerability_class: str,
    finding_ids: Sequence[str],
    evidence_node_ids: Sequence[str],
    evidence_edge_ids: Sequence[str],
    schema_version: str = "1.0",
) -> str:
    """Computes a deterministic SHA-256 assessment ID based on canonical payload serialization."""
    payload = {
        "schema": "E13-ASSESSMENT",
        "schema_version": schema_version,
        "cluster_id": cluster_id,
        "vulnerability_class": vulnerability_class,
        "finding_ids": sorted(set(str(x) for x in finding_ids)),
        "evidence_node_ids": sorted(set(str(x) for x in evidence_node_ids)),
        "evidence_edge_ids": sorted(set(str(x) for x in evidence_edge_ids)),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(f"E13-ASSESSMENT:{canonical}".encode()).hexdigest()


def generate_structured_explanation(
    cluster: VulnerabilityCluster,
    findings: Sequence[SecurityFinding],
    graph: EvidenceGraph | None = None,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Generates byte-for-byte reproducible explanation lines and limitations from evidence.

    NEVER calls LLM. NEVER uses eval()/exec().
    """
    explanations: list[str] = []
    limitations: list[str] = []

    vuln = cluster.vulnerability_class.upper()
    explanations.append(f"Vulnerability Cluster '{cluster.cluster_id[:8]}' classified as {vuln}.")
    explanations.append(f"Cluster Status is {cluster.status.value} with calibrated confidence score {cluster.confidence:.4f}.")
    explanations.append(f"Aggregated technical severity evaluated as {cluster.severity}.")

    finding_count = len(cluster.finding_ids)
    explanations.append(f"Correlated across {finding_count} security finding(s).")

    if cluster.source_fact_ids:
        explanations.append(f"Source evidence anchored by fact(s): {', '.join(cluster.source_fact_ids)}.")
    if cluster.sink_fact_ids:
        explanations.append(f"Sink evidence anchored by fact(s): {', '.join(cluster.sink_fact_ids)}.")
    if cluster.flow_ids:
        explanations.append(f"Dataflow traversal corroborated by flow(s): {', '.join(cluster.flow_ids)}.")

    has_blocked = False
    has_confirmed = False
    for f in findings:
        f_status = f.status.value if hasattr(f.status, "value") else str(f.status)
        if f_status == "BLOCKED":
            has_blocked = True
        elif f_status == "CONFIRMED":
            has_confirmed = True

    if has_blocked:
        explanations.append("Sanitizer barrier evidence observed on one or more correlated flows.")
    else:
        explanations.append("No valid sink-category sanitizer barrier was detected along correlated flow paths.")

    if has_confirmed and has_blocked:
        explanations.append("Correlated cluster contains both CONFIRMED and BLOCKED finding evidence; valid un-sanitized paths prevail for risk assessment.")

    # Standard analytical limitations
    limitations.append("Analysis is static and deterministic; runtime dynamic payload behavior was not executed.")
    limitations.append("CPG graph topology was held strictly immutable during rule and correlation evaluation.")
    if cluster.status == ClusterStatus.UNKNOWN:
        limitations.append("Cluster status is UNKNOWN due to incomplete SSA dataflow chains or un-resolvable node facts.")

    return tuple(explanations), tuple(limitations)


@dataclass(frozen=True)
class SecurityAssessment:
    """Immutable final security assessment encapsulating correlated vulnerability analysis, evidence graph references, and explanations."""

    assessment_id: str
    cluster_id: str
    vulnerability_class: str
    status: ClusterStatus
    severity: str
    confidence: float
    finding_ids: tuple[str, ...]
    evidence_node_ids: tuple[str, ...]
    evidence_edge_ids: tuple[str, ...]
    explanation: tuple[str, ...]
    limitations: tuple[str, ...]
    schema_version: str = "1.0"

    @classmethod
    def create(
        cls,
        cluster: VulnerabilityCluster,
        findings: Sequence[SecurityFinding],
        evidence_graph: EvidenceGraph | None = None,
        custom_explanation: Sequence[str] | None = None,
        custom_limitations: Sequence[str] | None = None,
        schema_version: str = "1.0",
    ) -> SecurityAssessment:
        """Factory constructing SecurityAssessment with deterministic identity."""
        f_ids = tuple(sorted(set(str(f) for f in cluster.finding_ids)))

        node_ids: tuple[str, ...] = ()
        edge_ids: tuple[str, ...] = ()

        if evidence_graph is not None:
            node_ids = tuple(sorted(set(n.node_id for n in evidence_graph.nodes)))
            edge_ids = tuple(sorted(set(e.edge_id for e in evidence_graph.edges)))

        aid = compute_assessment_id(
            cluster_id=cluster.cluster_id,
            vulnerability_class=cluster.vulnerability_class,
            finding_ids=f_ids,
            evidence_node_ids=node_ids,
            evidence_edge_ids=edge_ids,
            schema_version=schema_version,
        )

        if custom_explanation is not None and custom_limitations is not None:
            expl = tuple(custom_explanation)
            lims = tuple(custom_limitations)
        else:
            expl, lims = generate_structured_explanation(cluster, findings, evidence_graph)

        return cls(
            assessment_id=aid,
            cluster_id=cluster.cluster_id,
            vulnerability_class=cluster.vulnerability_class,
            status=cluster.status,
            severity=cluster.severity,
            confidence=cluster.confidence,
            finding_ids=f_ids,
            evidence_node_ids=node_ids,
            evidence_edge_ids=edge_ids,
            explanation=expl,
            limitations=lims,
            schema_version=schema_version,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serializes SecurityAssessment to canonical dictionary."""
        return {
            "assessment_id": self.assessment_id,
            "cluster_id": self.cluster_id,
            "vulnerability_class": self.vulnerability_class,
            "status": self.status.value,
            "severity": self.severity,
            "confidence": self.confidence,
            "finding_ids": list(self.finding_ids),
            "evidence_node_ids": list(self.evidence_node_ids),
            "evidence_edge_ids": list(self.evidence_edge_ids),
            "explanation": list(self.explanation),
            "limitations": list(self.limitations),
            "schema_version": self.schema_version,
        }
