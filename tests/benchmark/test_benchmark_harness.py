"""Phase 5A & 5B — Metric & Harness Verification Tests.

Verifies:
1. Independent GroundTruthProvider data loading
2. Canonical 6-tuple outcome classification (TP, FP, TN, FN, FN_EPISTEMIC, UNCERTAIN_TN)
3. Mathematical precision, strict recall, epistemic recall, F1, and epistemic uncertainty ratio
4. Provenance tracking via BenchmarkRun
"""

from karsasec.benchmark.harness import BenchmarkHarness
from karsasec.benchmark.models import GroundTruthManifest, GroundTruthStatus
from karsasec.benchmark.provider import GroundTruthProvider


def test_ground_truth_provider_ingestion() -> None:
    provider = GroundTruthProvider()
    manifest = GroundTruthManifest(
        test_case_id="TC_SQLI_01",
        dataset_name="OWASP_BENCHMARK",
        vulnerability_class="SQL_INJECTION",
        cwe="CWE-89",
        expected_status=GroundTruthStatus.VULNERABLE,
        file_path="BenchmarkTest00001.java",
        line_number=45,
        sink_function="executeQuery",
    )
    provider.register_manifest(manifest)

    m = provider.get_manifest("TC_SQLI_01")
    assert m is not None
    assert m.vulnerability_class == "SQL_INJECTION"
    assert m.expected_status == GroundTruthStatus.VULNERABLE


def test_canonical_6_tuple_outcomes() -> None:
    manifests = [
        GroundTruthManifest("TC_01", "DS", "SQLI", "CWE-89", GroundTruthStatus.VULNERABLE, "f1.java"), # GT: VULN
        GroundTruthManifest("TC_02", "DS", "SQLI", "CWE-89", GroundTruthStatus.VULNERABLE, "f2.java"), # GT: VULN
        GroundTruthManifest("TC_03", "DS", "SQLI", "CWE-89", GroundTruthStatus.VULNERABLE, "f3.java"), # GT: VULN
        GroundTruthManifest("TC_04", "DS", "SQLI", "CWE-89", GroundTruthStatus.SAFE,       "f4.java"), # GT: SAFE
        GroundTruthManifest("TC_05", "DS", "SQLI", "CWE-89", GroundTruthStatus.SAFE,       "f5.java"), # GT: SAFE
        GroundTruthManifest("TC_06", "DS", "SQLI", "CWE-89", GroundTruthStatus.SAFE,       "f6.java"), # GT: SAFE
    ]
    provider = GroundTruthProvider(manifests)
    harness = BenchmarkHarness(provider)

    predictions = {
        "TC_01": "VULNERABLE", # TP
        "TC_02": "SAFE",       # FN
        "TC_03": "UNKNOWN",    # FN_EPISTEMIC
        "TC_04": "VULNERABLE", # FP
        "TC_05": "SAFE",       # TN
        "TC_06": "CONFLICT",   # UNCERTAIN_TN
    }

    res = harness.evaluate_predictions(predictions, dataset_name="DS")

    assert res.total_cases == 6
    assert res.tp == 1
    assert res.fn == 1
    assert res.fn_epistemic == 1
    assert res.fp == 1
    assert res.tn == 1
    assert res.uncertain_tn == 1

    # Strict Precision = TP / (TP + FP) = 1 / (1 + 1) = 0.5
    assert res.strict_precision == 0.5

    # Strict Recall = TP / (TP + FN + FN_EPISTEMIC) = 1 / (1 + 1 + 1) = 1/3 = 0.3333
    assert abs(res.strict_recall - (1 / 3)) < 1e-4

    # Epistemic Recall = (TP + FN_EPISTEMIC) / 3 = 2 / 3 = 0.6667
    assert abs(res.epistemic_recall - (2 / 3)) < 1e-4

    # Epistemic Uncertainty Ratio = (UNKNOWN + CONFLICT) / Total = 2 / 6 = 0.3333
    assert abs(res.epistemic_uncertainty_ratio - (2 / 6)) < 1e-4


def test_benchmark_run_provenance() -> None:
    provider = GroundTruthProvider([
        GroundTruthManifest("TC_1", "DS", "XSS", "CWE-79", GroundTruthStatus.SAFE, "f.java")
    ])
    harness = BenchmarkHarness(provider, commit_sha="cbbb7fe4d088cd55212e97fe7928847103892d97")
    res = harness.evaluate_predictions({"TC_1": "SAFE"})

    assert res.run.commit_sha == "cbbb7fe4d088cd55212e97fe7928847103892d97"
    assert res.run.dataset_name == "OWASP_BENCHMARK"
    assert len(res.run.compute_hash()) == 16
