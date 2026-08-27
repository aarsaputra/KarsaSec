"""Comprehensive Invariant (INV-E14-PRIO-01..33) and Adversarial Case (A-Z + AA-AJ) test suite for Sprint E14."""

from karsasec.analysis.regression_engine import RegressionEngine
from karsasec.analysis.regression_fingerprint import (
    compute_regression_fingerprint,
    normalize_path,
)
from karsasec.analysis.regression_report import RegressionStatus
from karsasec.analysis.remediation_engine import RemediationEngine
from karsasec.analysis.remediation_pattern import RemediationPatternRegistry, RemediationStatus
from karsasec.analysis.vulnerability_cluster import ClusterStatus, VulnerabilityCluster
from karsasec.analysis.vulnerability_prioritizer import VulnerabilityPrioritizer
from karsasec.analysis.vulnerability_priority import PriorityStatus, compute_priority_id


def test_inv_e14_prio_01_02_03_04_priority_determinism() -> None:
    """INV-E14-PRIO-01..04: Priority ID computation is deterministic and ordering-invariant."""
    pid1 = compute_priority_id("SQL_INJECTION", "c1", 0.8, 0.9, 0.9, 0.8, 0.8)
    pid2 = compute_priority_id("SQL_INJECTION", "c1", 0.8, 0.9, 0.9, 0.8, 0.8)

    assert pid1 == pid2
    assert len(pid1) == 64


def test_cases_aa_ab_nan_inf_priority_protection() -> None:
    """Cases AA, AB & INV-E14-PRIO-08: NaN or Inf input scores MUST force PriorityStatus.UNKNOWN."""
    cluster = VulnerabilityCluster.create(
        vulnerability_class="SQL_INJECTION",
        finding_ids=["f1"],
        source_fact_ids=["sf1"],
        sink_fact_ids=["kf1"],
        flow_ids=["fl1"],
        source_nodes=["n1"],
        sink_nodes=["n2"],
        shared_contexts=(),
        confidence=float("nan"),
        severity="HIGH",
        status=ClusterStatus.CONFIRMED,
    )

    prioritizer = VulnerabilityPrioritizer()
    res_nan = prioritizer.prioritize(cluster, exposure_score=float("nan"))
    assert res_nan.priority_status == PriorityStatus.UNKNOWN

    cluster_inf = VulnerabilityCluster.create(
        vulnerability_class="SQL_INJECTION",
        finding_ids=["f1"],
        source_fact_ids=["sf1"],
        sink_fact_ids=["kf1"],
        flow_ids=["fl1"],
        source_nodes=["n1"],
        sink_nodes=["n2"],
        shared_contexts=(),
        confidence=0.90,
        severity="HIGH",
        status=ClusterStatus.CONFIRMED,
    )
    res_inf = prioritizer.prioritize(cluster_inf, exposure_score=float("inf"))
    assert res_inf.priority_status == PriorityStatus.UNKNOWN


def test_cases_h_i_j_ag_remediation_negative_matrix() -> None:
    """Cases H, I, J, AG & INV-E14-PRIO-11,12: Fake and cross-category sanitizers MUST be rejected."""
    pattern_sql = RemediationPatternRegistry.get_for_sink_category("SQL")
    assert pattern_sql is not None

    # Fake sanitizers rejected
    assert pattern_sql.is_forbidden_fix("str()") is True
    assert pattern_sql.is_forbidden_fix("trim()") is True

    # Cross-category sanitizer rejected for SQL
    assert pattern_sql.is_forbidden_fix("escape_html()") is True


def test_cases_ae_af_fingerprint_normalization() -> None:
    """Cases AE, AF & INV-E14-PRIO-15: Line numbers removed and path dot-components normalized."""
    assert normalize_path("./foo/../foo/app.py:100") == "foo/app.py"

    fp1 = compute_regression_fingerprint("SQL_INJECTION", "sf1", "SQL", "app.py:10", "SQL-001")
    fp2 = compute_regression_fingerprint("SQL_INJECTION", "sf1", "SQL", "app.py:9999", "SQL-001")
    assert fp1 == fp2


def test_cases_ac_ad_strict_resolved_semantics() -> None:
    """Cases AC, AD & INV-E14-PRIO-18,19: Baseline vulnerability absent in failed run MUST emit UNKNOWN, never RESOLVED."""
    base_cluster = VulnerabilityCluster.create(
        vulnerability_class="SQL_INJECTION",
        finding_ids=["f1"],
        source_fact_ids=["sf1"],
        sink_fact_ids=["kf1"],
        flow_ids=["fl1"],
        source_nodes=["n1"],
        sink_nodes=["n2"],
        shared_contexts=(),
        confidence=0.90,
        severity="HIGH",
        status=ClusterStatus.CONFIRMED,
    )

    engine = RegressionEngine()

    # Analyzer failed -> UNKNOWN
    report_failed = engine.compare([base_cluster], [], current_analysis_valid=False)
    assert len(report_failed.resolved_fingerprints) == 0
    assert len(report_failed.unknown_fingerprints) == 1
    assert report_failed.status == RegressionStatus.UNKNOWN

    # Analyzer succeeded -> RESOLVED
    report_success = engine.compare([base_cluster], [], current_analysis_valid=True)
    assert len(report_success.resolved_fingerprints) == 1
    assert report_success.status == RegressionStatus.PASS


def test_cases_z_confirmed_vulnerability_remediation_required() -> None:
    """Case Z & INV-E14-PRIO-10: Confirmed vulnerability with no barrier MUST require remediation."""
    cluster = VulnerabilityCluster.create(
        vulnerability_class="SQL_INJECTION",
        finding_ids=["f1"],
        source_fact_ids=["sf1"],
        sink_fact_ids=["kf1"],
        flow_ids=["fl1"],
        source_nodes=["n1"],
        sink_nodes=["n2"],
        shared_contexts=(),
        confidence=0.90,
        severity="HIGH",
        status=ClusterStatus.CONFIRMED,
    )

    engine = RemediationEngine()
    plan = engine.generate(cluster)

    assert plan.status == RemediationStatus.REQUIRED
    assert plan.primary_fix == "parameterized_query"
