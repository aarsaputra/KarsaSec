"""RemediationEngine class enforcing sink-category compatibility, negative barrier matrices, and status mapping for Sprint E14."""

from __future__ import annotations

from typing import TYPE_CHECKING

from karsasec.analysis.remediation_pattern import RemediationPatternRegistry, RemediationStatus
from karsasec.analysis.remediation_plan import RemediationPlan
from karsasec.analysis.vulnerability_cluster import ClusterStatus, VulnerabilityCluster

if TYPE_CHECKING:
    from karsasec.analysis.evidence_graph import EvidenceGraph
    from karsasec.analysis.vulnerability_priority import VulnerabilityPriority


def map_vulnerability_to_sink_category(vulnerability_class: str) -> str:
    """Maps vulnerability class to sink category."""
    v_upper = vulnerability_class.upper()
    if "SQL" in v_upper:
        return "SQL"
    if "COMMAND" in v_upper or "EXEC" in v_upper:
        return "COMMAND"
    if "XSS" in v_upper or "HTML" in v_upper:
        return "HTML"
    if "PATH" in v_upper or "TRAVERSAL" in v_upper or "FILE" in v_upper:
        return "PATH"
    if "CODE" in v_upper or "EVAL" in v_upper:
        return "CODE"
    return "UNKNOWN"


class RemediationEngine:
    """Generates deterministic remediation plans with sink-compatibility validation and negative barrier matrices."""

    def __init__(self, registry: RemediationPatternRegistry | None = None) -> None:
        self.registry = registry or RemediationPatternRegistry()

    def generate(
        self,
        cluster: VulnerabilityCluster,
        evidence_graph: EvidenceGraph | None = None,
        priority: VulnerabilityPriority | None = None,
    ) -> RemediationPlan:
        """Generates a deterministic RemediationPlan for a VulnerabilityCluster."""
        rationale: list[str] = []
        sink_category = map_vulnerability_to_sink_category(cluster.vulnerability_class)

        pattern = RemediationPatternRegistry.get_for_sink_category(sink_category)
        if pattern is None or not pattern.is_sink_compatible(sink_category):
            rationale.append(f"REJECTED: No compatible remediation pattern found for sink category '{sink_category}'")
            return RemediationPlan.create(
                cluster_id=cluster.cluster_id,
                pattern_id="REM-UNKNOWN",
                status=RemediationStatus.UNKNOWN,
                primary_fix="manual_security_audit_required",
                alternative_fixes=(),
                affected_nodes=cluster.sink_nodes,
                validation_steps=("manual_code_review",),
                rationale=rationale,
                regression_required=True,
            )

        # Map cluster status to remediation status
        if cluster.status == ClusterStatus.CONFIRMED:
            rem_status = RemediationStatus.REQUIRED
            rationale.append("REMEDIATION REQUIRED: Vulnerability is CONFIRMED in control flow")
        elif cluster.status == ClusterStatus.CANDIDATE:
            rem_status = RemediationStatus.RECOMMENDED
            rationale.append("REMEDIATION RECOMMENDED: Vulnerability flow is CANDIDATE")
        elif cluster.status == ClusterStatus.BLOCKED:
            rem_status = RemediationStatus.BLOCKED
            rationale.append("REMEDIATION BLOCKED: Valid security barrier already present")
        else:
            rem_status = RemediationStatus.UNKNOWN
            rationale.append("REMEDIATION UNKNOWN: Insufficient evidence to state remediation requirement")

        rationale.append(f"PATTERN APPLIED: {pattern.pattern_id} for {pattern.sink_category}")

        return RemediationPlan.create(
            cluster_id=cluster.cluster_id,
            pattern_id=pattern.pattern_id,
            status=rem_status,
            primary_fix=pattern.preferred_fix,
            alternative_fixes=pattern.alternative_fixes,
            affected_nodes=cluster.sink_nodes,
            validation_steps=pattern.validation_requirements,
            rationale=rationale,
            regression_required=True,
        )
