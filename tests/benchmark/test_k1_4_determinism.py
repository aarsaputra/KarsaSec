"""K1.4 Determinism & Order Invariance Test Suite (Task K1.4)."""

import json
from pathlib import Path

from karsasec.analysis.taint.k1_integrated import analyze_k1


def test_k1_4_10_pass_repeatability() -> None:
    with open("benchmarks/k1/manifest.json", encoding="utf-8") as f:
        m = json.load(f)

    for case in m["cases"]:
        code = Path(case["source_file"]).read_text(encoding="utf-8")

        base_res = analyze_k1(code)
        for _ in range(9):
            repeat_res = analyze_k1(code)
            assert base_res == repeat_res, f"Non-deterministic analysis for {case['case_id']}"


def test_k1_4_order_invariance() -> None:
    with open("benchmarks/k1/manifest.json", encoding="utf-8") as f:
        m = json.load(f)

    cases = m["cases"]
    order1 = cases[:10]
    order2 = list(reversed(cases[:10]))

    res_order1 = {c["case_id"]: analyze_k1(Path(c["source_file"]).read_text(encoding="utf-8")) for c in order1}
    res_order2 = {c["case_id"]: analyze_k1(Path(c["source_file"]).read_text(encoding="utf-8")) for c in order2}

    assert res_order1 == res_order2
