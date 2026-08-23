"""K1.4 Integrated 40-Case Evaluation Test Suite (Task K1.4)."""

import json
from pathlib import Path

from karsasec.analysis.taint.k1_integrated import analyze_k1


def test_k1_4_full_40_case_integrated_evaluation() -> None:
    with open("benchmarks/k1/manifest.json", encoding="utf-8") as f:
        m = json.load(f)
    with open("benchmarks/k1/holdout_manifest.json", encoding="utf-8") as f:
        hm = json.load(f)

    all_cases = m["cases"] + hm["cases"]
    seen = set()
    cases = []
    for c in all_cases:
        if c["case_id"] not in seen:
            seen.add(c["case_id"])
            cases.append(c)

    assert len(cases) == 40

    tp = 0
    tn = 0
    fp = 0
    fn = 0

    for case in cases:
        code = Path(case["source_file"]).read_text(encoding="utf-8")
        findings = analyze_k1(code)

        if case["expected_status"] == "TRUE_POSITIVE":
            if len(findings) > 0:
                tp += 1
            else:
                fn += 1
        elif case["expected_status"] == "TRUE_NEGATIVE":
            if len(findings) == 0:
                tn += 1
            else:
                fp += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0

    assert tp == 22, f"Expected 22 TPs, got {tp}"
    assert tn == 18, f"Expected 18 TNs, got {tn}"
    assert fp == 0, f"Expected 0 FPs, got {fp}"
    assert fn == 0, f"Expected 0 FNs, got {fn}"

    assert precision == 1.0
    assert recall == 1.0
