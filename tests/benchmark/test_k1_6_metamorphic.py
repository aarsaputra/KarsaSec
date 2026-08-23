"""K1.6 Metamorphic Security Equivalence Test Suite.

Verifies INV-K1.6-04: Asserts D(source) == D(T(source)) for 7 semantic-preserving transformations.
"""

import json
from pathlib import Path

from karsasec.analysis.taint.k1_integrated import analyze_k1
from karsasec.benchmark.k1_differential import normalize_finding
from karsasec.benchmark.k1_metamorphic import K1MetamorphicEngine


def test_k1_6_metamorphic_semantic_equivalence() -> None:
    manifest_p = Path("benchmarks/k1/manifest.json")
    with open(manifest_p, encoding="utf-8") as f:
        m = json.load(f)

    dev_cases = [c for c in m["cases"] if c["partition"] == "development"]
    assert len(dev_cases) == 20

    engine = K1MetamorphicEngine()
    transformations = [
        "M1_IDENTIFIER_RENAME",
        "M2_ASSIGNMENT_ALIAS",
        "M3_INTERMEDIATE_VARIABLE",
        "M4_EQUIVALENT_EXPRESSION",
        "M5_DEAD_CODE",
        "M6_FORMATTING_NOISE",
        "M7_HELPER_WRAPPER",
    ]

    total_eval = 0
    equivalent_count = 0

    for case in dev_cases:
        orig_code = Path(case["source_file"]).read_text(encoding="utf-8")
        orig_findings = [normalize_finding(f) for f in analyze_k1(orig_code)]

        for trans in transformations:
            meta_case = engine.generate_metamorphic_case(case["case_id"], orig_code, trans)
            if not meta_case.semantic_equivalent:
                continue

            total_eval += 1
            trans_findings = [normalize_finding(f) for f in analyze_k1(meta_case.transformed_source)]

            if orig_findings == trans_findings:
                equivalent_count += 1
            else:
                raise AssertionError(
                    f"Metamorphic mismatch for {case['case_id']} under {trans}: "
                    f"orig={orig_findings}, transformed={trans_findings}"
                )

    assert total_eval > 0
    assert (
        equivalent_count == total_eval
    ), f"Metamorphic equivalence rate {equivalent_count}/{total_eval} below 100%"
