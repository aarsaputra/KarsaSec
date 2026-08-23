"""K1.4 Safe Control Matrix Test Suite (Task K1.4)."""

import json
from pathlib import Path

from karsasec.analysis.taint.k1_integrated import analyze_k1


def test_k1_4_all_18_safe_controls_zero_false_positives() -> None:
    with open("benchmarks/k1/manifest.json", encoding="utf-8") as f:
        m = json.load(f)
    with open("benchmarks/k1/holdout_manifest.json", encoding="utf-8") as f:
        hm = json.load(f)

    all_cases = m["cases"] + hm["cases"]
    seen = set()
    safe_cases = []
    for c in all_cases:
        if c["case_id"] not in seen and c["expected_status"] == "TRUE_NEGATIVE":
            seen.add(c["case_id"])
            safe_cases.append(c)

    assert len(safe_cases) == 18, f"Expected 18 safe control cases, got {len(safe_cases)}"

    for case in safe_cases:
        code = Path(case["source_file"]).read_text(encoding="utf-8")
        findings = analyze_k1(code)
        assert len(findings) == 0, f"False positive generated for safe control {case['case_id']}: {findings}"
