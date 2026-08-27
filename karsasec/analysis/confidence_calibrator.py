"""ConfidenceCalibrator implementing evidence diversity scoring across 8 dimensions, status calibration, and severity aggregation for Sprint E13."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

from karsasec.analysis.vulnerability_cluster import ClusterStatus

if TYPE_CHECKING:
    from karsasec.analysis.evidence_graph import EvidenceGraph
    from karsasec.analysis.security_finding import SecurityFinding

logger = logging.getLogger("karsasec.analysis.confidence_calibrator")

SEVERITY_RANK: dict[str, int] = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}


@dataclass(frozen=True)
class CalibrationResult:
    """Result of confidence calibration and status/severity aggregation."""

    calibrated_confidence: float
    status: ClusterStatus
    severity: str
    evidence_diversity: float
    unique_dimensions: tuple[str, ...]


class ConfidenceCalibrator:
    """Calibrates cluster confidence based on independent evidence dimensions, preventing duplicate finding inflation."""

    def calibrate(
        self,
        findings: Sequence[SecurityFinding],
        graph: EvidenceGraph | None = None,
    ) -> CalibrationResult:
        """Calibrates confidence, status, and severity for a correlated group of findings.

        INV-E13-CORR-07: Duplicate findings MUST NOT inflate calibrated confidence.
        """
        if not findings:
            return CalibrationResult(
                calibrated_confidence=0.0,
                status=ClusterStatus.UNKNOWN,
                severity="INFO",
                evidence_diversity=0.0,
                unique_dimensions=(),
            )

        # 1. Base confidence from strongest finding
        base_confidence = max(f.confidence for f in findings)

        # 2. Extract unique evidence across 8 dimensions
        unique_sources: set[str] = set()
        unique_sinks: set[str] = set()
        unique_flows: set[str] = set()
        unique_ssa: set[str] = set()
        unique_contexts: set[str] = set()
        unique_sanitizers: set[str] = set()
        unique_frameworks: set[str] = set()
        unique_rules: set[str] = set()

        has_unknown_status = False
        has_blocked_status = False
        has_confirmed_status = False

        for f in findings:
            unique_sources.add(f.source_fact_id)
            unique_sinks.add(f.sink_fact_id)
            unique_flows.add(f.flow_id)
            unique_rules.add(f.rule_key)

            f_status = f.status.value if hasattr(f.status, "value") else str(f.status)
            if f_status == "UNKNOWN":
                has_unknown_status = True
            elif f_status == "BLOCKED":
                has_blocked_status = True
            elif f_status == "CONFIRMED":
                has_confirmed_status = True

            # Extract evidence fields from forensic dictionaries
            src_dict = dict(f.source_evidence)
            if "semantic_role" in src_dict:
                unique_sources.add(src_dict["semantic_role"])

            snk_dict = dict(f.sink_evidence)
            if "semantic_role" in snk_dict:
                unique_sinks.add(snk_dict["semantic_role"])

            fl_dict = dict(f.flow_evidence)
            if "path_node_count" in fl_dict:
                unique_flows.add(f"count:{fl_dict['path_node_count']}")

            san_dict = dict(f.sanitizer_evidence)
            if san_dict.get("has_valid_barrier") == "True":
                unique_sanitizers.add(san_dict.get("barrier_name", "barrier"))

        # Calculate evidence independence bonuses
        source_independence = 1.0 if len(unique_sources) > 1 else 0.0
        sink_independence = 1.0 if len(unique_sinks) > 1 else 0.0
        context_independence = 1.0 if len(unique_contexts) > 1 else 0.0
        corroboration = 1.0 if len(unique_flows) > 1 or len(unique_rules) > 1 else 0.0

        # Calculate calibrated confidence
        raw_calibrated = (
            base_confidence
            + 0.10 * source_independence
            + 0.10 * sink_independence
            + 0.05 * context_independence
            + 0.05 * corroboration
        )
        calibrated_confidence = max(0.0, min(1.0, round(raw_calibrated, 4)))

        # Calculate evidence diversity across 8 dimensions
        dimensions = {
            "SOURCE": unique_sources,
            "SINK": unique_sinks,
            "FLOW": unique_flows,
            "SSA": unique_ssa,
            "CALL_CONTEXT": unique_contexts,
            "SANITIZER": unique_sanitizers,
            "FRAMEWORK": unique_frameworks,
            "RULE": unique_rules,
        }
        active_dims = tuple(sorted(k for k, v in dimensions.items() if len(v) > 0))
        evidence_diversity = round(len(active_dims) / 8.0, 4)

        # 3. Status Calibration Decision Algorithm
        all_blocked = all(
            (f.status.value if hasattr(f.status, "value") else str(f.status)) == "BLOCKED"
            for f in findings
        )

        if has_unknown_status and not has_confirmed_status and not has_blocked_status:
            cluster_status = ClusterStatus.UNKNOWN
        elif all_blocked:
            cluster_status = ClusterStatus.BLOCKED
        elif has_confirmed_status and calibrated_confidence >= 0.85:
            cluster_status = ClusterStatus.CONFIRMED
        elif calibrated_confidence >= 0.60:
            cluster_status = ClusterStatus.CANDIDATE
        else:
            cluster_status = ClusterStatus.UNKNOWN

        # 4. Severity Aggregation
        non_blocked_severities = [
            f.severity.upper()
            for f in findings
            if (f.status.value if hasattr(f.status, "value") else str(f.status)) != "BLOCKED"
        ]

        if non_blocked_severities:
            cluster_severity = max(non_blocked_severities, key=lambda s: SEVERITY_RANK.get(s, 0))
        else:
            cluster_severity = max((f.severity.upper() for f in findings), key=lambda s: SEVERITY_RANK.get(s, 0))

        return CalibrationResult(
            calibrated_confidence=calibrated_confidence,
            status=cluster_status,
            severity=cluster_severity,
            evidence_diversity=evidence_diversity,
            unique_dimensions=active_dims,
        )
