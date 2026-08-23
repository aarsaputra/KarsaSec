"""K1.6 Differential Regression Test Suite.

Verifies INV-K1.6-02 and INV-K1.6-12: Compares normalized findings of the current
detector against the immutable K1.4 baseline finding snapshot across all 40 original fixtures.
"""

import json
from pathlib import Path

from karsasec.analysis.taint.k1_integrated import analyze_k1
from karsasec.benchmark.k1_differential import compare_detectors


def test_k1_6_differential_equivalence_against_k1_4_baseline() -> None:
    snapshot_p = Path("benchmarks/k1/baseline/k1_4_findings.json")
    with open(snapshot_p, encoding="utf-8") as f:
        snapshot = json.load(f)

    mismatches = []
    added_total = 0
    removed_total = 0

    for case_id, info in snapshot.items():
        source_p = Path(info["source_file"])
        code = source_p.read_text(encoding="utf-8")
        current_findings = analyze_k1(code)
        baseline_findings = info["normalized_findings"]

        diff = compare_detectors(case_id, baseline_findings, current_findings)

        if diff.status != "EQUIVALENT":
            mismatches.append(diff)
            added_total += len(diff.added_findings)
            removed_total += len(diff.removed_findings)

    assert (
        len(mismatches) == 0
    ), f"Differential regression detected across {len(mismatches)} fixtures! Added: {added_total}, Removed: {removed_total}. Details: {mismatches}"
