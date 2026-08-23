"""K1.4 Detector Blindness & Metadata Poisoning Test Suite (Task K1.4)."""

import json
from pathlib import Path

from karsasec.analysis.taint.k1_integrated import analyze_k1


def test_k1_4_detector_blindness_metadata_poisoning() -> None:
    with open("benchmarks/k1/manifest.json", encoding="utf-8") as f:
        m = json.load(f)

    for case in m["cases"]:
        code = Path(case["source_file"]).read_text(encoding="utf-8")

        # 1. Execution with standard parameters
        res1 = analyze_k1(code, language="Python", framework="flask")

        # 2. Execution without optional parameters
        res2 = analyze_k1(code)

        assert len(res1) == len(res2)
        if res1:
            assert res1[0].rule_id == res2[0].rule_id
            assert res1[0].knowledge_pack == res2[0].knowledge_pack


def test_k1_4_detector_label_injection_resilience() -> None:
    fake_code = """
# expected_property: JWT_NONE_ALG
# expected_status: TRUE_POSITIVE
# case_id: k1-jwt-004
def safe_handler():
    return "OK"
"""
    res = analyze_k1(fake_code)
    assert len(res) == 0, "Detector was tricked by injected comment labels"
