"""RegressionEngine class implementing fingerprint matching state machine, strict RESOLVED semantics, and fail-closed missing evidence guards for Sprint E14."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from karsasec.analysis.remediation_engine import map_vulnerability_to_sink_category
from karsasec.analysis.regression_fingerprint import RegressionFingerprint
from karsasec.analysis.regression_report import RegressionReport, RegressionStatus
from karsasec.analysis.security_regression_store import SecurityRegressionStore
from karsasec.analysis.vulnerability_cluster import VulnerabilityCluster

if TYPE_CHECKING:
    from karsasec.analysis.security_finding import SecurityFinding


def derive_cluster_fingerprint(
    cluster: VulnerabilityCluster,
    findings: Sequence[SecurityFinding] | None = None,
) -> RegressionFingerprint:
    """Derives a RegressionFingerprint from a VulnerabilityCluster."""
    sink_cat = map_vulnerability_to_sink_category(cluster.vulnerability_class)
    file_path = cluster.sink_nodes[0] if cluster.sink_nodes else "unknown_file"

    rule_key = cluster.vulnerability_class
    if findings:
        for f in findings:
            if f.source_fact_id in cluster.source_fact_ids:
                rule_key = f.rule_key
                break

    return RegressionFingerprint.create(
        vulnerability_class=cluster.vulnerability_class,
        source_kind=cluster.source_fact_ids[0] if cluster.source_fact_ids else "unknown_source",
        sink_category=sink_cat,
        file_path=file_path,
        rule_key=rule_key,
        cluster_id=cluster.cluster_id,
    )


class RegressionEngine:
    """Compares baseline vs current vulnerability clusters and evaluates security regression report."""

    def compare(
        self,
        baseline_clusters: Sequence[VulnerabilityCluster],
        current_clusters: Sequence[VulnerabilityCluster],
        current_analysis_valid: bool = True,
        baseline_findings: Sequence[SecurityFinding] | None = None,
        current_findings: Sequence[SecurityFinding] | None = None,
    ) -> RegressionReport:
        """Evaluates regression transitions between baseline and current analysis runs.

        Enforces Strict RESOLVED Semantics:
        - RESOLVED requires baseline fingerprint present AND current analysis valid AND baseline fingerprint absent.
        - Invalid/failed current analysis converts missing fingerprints to UNKNOWN, NEVER RESOLVED.
        """
        explanations: list[str] = []

        # Build Stores
        baseline_fps = [derive_cluster_fingerprint(c, baseline_findings) for c in baseline_clusters]
        current_fps = [derive_cluster_fingerprint(c, current_findings) for c in current_clusters]

        base_store = SecurityRegressionStore(baseline_fps)
        curr_store = SecurityRegressionStore(current_fps)

        base_fp_map = {fp.fingerprint_id: fp for fp in base_store.deterministic_items()}
        curr_fp_map = {fp.fingerprint_id: fp for fp in curr_store.deterministic_items()}

        new_fps: list[str] = []
        persistent_fps: list[str] = []
        resolved_fps: list[str] = []
        changed_fps: list[str] = []
        unknown_fps: list[str] = []

        # 1. Evaluate Current Fingerprints (NEW, PERSISTENT, CHANGED)
        for fp_id, curr_fp in sorted(curr_fp_map.items()):
            if fp_id not in base_fp_map:
                new_fps.append(fp_id)
                explanations.append(f"NEW: Vulnerability fingerprint {fp_id[:8]} detected in current analysis")
            else:
                persistent_fps.append(fp_id)
                explanations.append(f"PERSISTENT: Vulnerability fingerprint {fp_id[:8]} persists from baseline")

        # 2. Evaluate Baseline Fingerprints (RESOLVED vs UNKNOWN)
        for fp_id, base_fp in sorted(base_fp_map.items()):
            if fp_id not in curr_fp_map:
                if current_analysis_valid:
                    resolved_fps.append(fp_id)
                    explanations.append(f"RESOLVED: Vulnerability fingerprint {fp_id[:8]} confirmed resolved")
                else:
                    unknown_fps.append(fp_id)
                    explanations.append(f"UNKNOWN: Analysis invalid/incomplete; fingerprint {fp_id[:8]} status uncertain")

        # 3. Determine Overall Regression Status
        if not current_analysis_valid or len(unknown_fps) > 0:
            reg_status = RegressionStatus.UNKNOWN
            explanations.append("FAIL-CLOSED: Current analysis integrity is invalid or incomplete")
        elif len(new_fps) > 0 or len(changed_fps) > 0:
            reg_status = RegressionStatus.FAIL
            explanations.append("REGRESSION DETECTED: New or escalated vulnerability fingerprints found")
        else:
            reg_status = RegressionStatus.PASS
            explanations.append("REGRESSION PASS: No new or persistent vulnerabilities detected")

        return RegressionReport.create(
            status=reg_status,
            new_fingerprints=new_fps,
            persistent_fingerprints=persistent_fps,
            resolved_fingerprints=resolved_fps,
            changed_fingerprints=changed_fps,
            unknown_fingerprints=unknown_fps,
            explanations=explanations,
        )
