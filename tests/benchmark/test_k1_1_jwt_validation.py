"""K1.1 JWT Knowledge Pack Evaluation Test Suite (Task K1.1)."""

import json
from pathlib import Path

from karsasec.analysis.taint.jwt import JWTAnalyzer


def test_k1_1_jwt_dev_partition_evaluation() -> None:
    manifest_p = Path("benchmarks/k1/manifest.json")
    with open(manifest_p, encoding="utf-8") as f:
        manifest = json.load(f)

    analyzer = JWTAnalyzer()
    dev_jwt_cases = [c for c in manifest["cases"] if c["partition"] == "development" and "jwt" in c["case_id"]]
    assert len(dev_jwt_cases) == 8

    tp_count = 0
    tn_count = 0

    for case in dev_jwt_cases:
        code = Path(case["source_file"]).read_text(encoding="utf-8")
        findings = analyzer.analyze_code(code, case["language"])

        if case["expected_status"] == "TRUE_POSITIVE":
            assert len(findings) > 0, f"Failed to detect TP for {case['case_id']}"
            tp_count += 1
        elif case["expected_status"] == "TRUE_NEGATIVE":
            assert len(findings) == 0, f"False positive triggered for {case['case_id']}"
            tn_count += 1

    assert tp_count == 5
    assert tn_count == 3


def test_k1_1_jwt_val_partition_evaluation() -> None:
    manifest_p = Path("benchmarks/k1/manifest.json")
    with open(manifest_p, encoding="utf-8") as f:
        manifest = json.load(f)

    analyzer = JWTAnalyzer()
    val_jwt_cases = [c for c in manifest["cases"] if c["partition"] == "validation" and "jwt" in c["case_id"]]
    assert len(val_jwt_cases) == 3

    tp_count = 0
    tn_count = 0

    for case in val_jwt_cases:
        code = Path(case["source_file"]).read_text(encoding="utf-8")
        findings = analyzer.analyze_code(code, case["language"])

        if case["expected_status"] == "TRUE_POSITIVE":
            assert len(findings) > 0, f"Failed to detect TP for {case['case_id']}"
            tp_count += 1
        elif case["expected_status"] == "TRUE_NEGATIVE":
            assert len(findings) == 0, f"False positive triggered for {case['case_id']}"
            tn_count += 1

    assert tp_count == 2
    assert tn_count == 1


def test_k1_1_jwt_holdout_blind_evaluation() -> None:
    manifest_p = Path("benchmarks/k1/holdout_manifest.json")
    with open(manifest_p, encoding="utf-8") as f:
        manifest = json.load(f)

    analyzer = JWTAnalyzer()
    holdout_jwt_cases = [c for c in manifest["cases"] if "jwt" in c["case_id"]]
    assert len(holdout_jwt_cases) == 3

    tp_count = 0
    tn_count = 0

    for case in holdout_jwt_cases:
        code = Path(case["source_file"]).read_text(encoding="utf-8")
        findings = analyzer.analyze_code(code, case["language"])

        if case["expected_status"] == "TRUE_POSITIVE":
            assert len(findings) > 0, f"Failed blind holdout TP for {case['case_id']}"
            tp_count += 1
        elif case["expected_status"] == "TRUE_NEGATIVE":
            assert len(findings) == 0, f"False positive on blind holdout TN for {case['case_id']}"
            tn_count += 1

    assert tp_count == 1
    assert tn_count == 2
