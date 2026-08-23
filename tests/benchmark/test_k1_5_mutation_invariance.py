"""K1.5 Dynamic Mutation Invariance Test Suite (Task K1.5)."""

import json
from pathlib import Path

from karsasec.analysis.taint.k1_integrated import analyze_k1
from karsasec.benchmark.k1_mutation_engine import K1MutationEngine


def test_k1_5_dynamic_mutation_semantic_invariance() -> None:
    manifest_p = Path("benchmarks/k1/manifest.json")
    with open(manifest_p, encoding="utf-8") as f:
        m = json.load(f)

    # Use Development partition cases exclusively
    dev_cases = [c for c in m["cases"] if c["partition"] == "development"]
    assert len(dev_cases) == 20

    engine = K1MutationEngine()
    mutation_types = ["M1", "M2", "M3", "M5", "M6", "M7"]

    for case in dev_cases:
        orig_code = Path(case["source_file"]).read_text(encoding="utf-8")
        orig_findings = analyze_k1(orig_code)

        for m_type in mutation_types:
            mut_case = engine.generate_mutation(case["case_id"], orig_code, m_type)
            mut_findings = analyze_k1(mut_case.mutated_code)

            # Verification: Mutated code must produce identical vulnerability finding counts
            assert len(mut_findings) == len(orig_findings), (
                f"Mutation {m_type} altered findings for {case['case_id']}: "
                f"orig={len(orig_findings)}, mut={len(mut_findings)}"
            )
            if orig_findings:
                assert mut_findings[0].knowledge_pack == orig_findings[0].knowledge_pack
