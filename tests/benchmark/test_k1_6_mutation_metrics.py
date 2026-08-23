"""K1.6 Per-Class Mutation Kill-Rate Metrics Test Suite.

Verifies INV-K1.6-05 & INV-K1.6-F06: Calculates MutationKillRate = killed / eligible across M1-M8.
Enforces denominator integrity: killed + survived == eligible and eligible > 0.
"""

import ast
import json
from pathlib import Path

from karsasec.analysis.taint.k1_integrated import analyze_k1
from karsasec.benchmark.k1_mutation_engine import K1MutationEngine


def test_k1_6_mutation_kill_rate_per_class() -> None:
    manifest_p = Path("benchmarks/k1/manifest.json")
    with open(manifest_p, encoding="utf-8") as f:
        m = json.load(f)

    # Use vulnerable Development cases
    dev_vuln_cases = [c for c in m["cases"] if c["partition"] == "development" and c["expected_status"] == "TRUE_POSITIVE"]
    assert len(dev_vuln_cases) == 11

    engine = K1MutationEngine()
    mutation_types = ["M1", "M2", "M3", "M4", "M5", "M6", "M7"]

    per_class_results = {}

    for m_type in mutation_types:
        eligible_count = 0
        killed_count = 0
        survived_count = 0

        for case in dev_vuln_cases:
            orig_code = Path(case["source_file"]).read_text(encoding="utf-8")
            mut_case = engine.generate_mutation(case["case_id"], orig_code, m_type)

            # Check eligibility (valid Python syntax)
            try:
                ast.parse(mut_case.mutated_code)
                eligible_count += 1
            except SyntaxError:
                continue

            findings = analyze_k1(mut_case.mutated_code)
            if len(findings) > 0:
                killed_count += 1
            else:
                survived_count += 1

        # Denominator Integrity Invariant (INV-K1.6-F06)
        assert eligible_count > 0, f"Eligible count for {m_type} must be > 0"
        assert (
            killed_count + survived_count == eligible_count
        ), f"Denominator mismatch for {m_type}: killed ({killed_count}) + survived ({survived_count}) != eligible ({eligible_count})"

        kill_rate = killed_count / eligible_count
        per_class_results[m_type] = {
            "eligible": eligible_count,
            "killed": killed_count,
            "survived": survived_count,
            "kill_rate": kill_rate,
        }

        assert (
            kill_rate >= 0.90
        ), f"Mutation kill rate for {m_type} is {kill_rate:.4f} ({killed_count}/{eligible_count}), below 0.90 threshold"

    assert len(per_class_results) == len(mutation_types)

    # M8 Safe-Control Adversarial Mutation Kill Rate Audit
    neg_dir = Path("benchmarks/k1/adversarial_semantic_negative")
    neg_cases = list(neg_dir.glob("*.py"))
    assert len(neg_cases) == 15

    m8_eligible = 0
    m8_safe_pass = 0

    for fix_p in neg_cases:
        code = fix_p.read_text(encoding="utf-8")
        try:
            ast.parse(code)
            m8_eligible += 1
        except SyntaxError:
            continue

        findings = analyze_k1(code)
        if len(findings) == 0:
            m8_safe_pass += 1

    assert m8_eligible == 15
    assert m8_safe_pass == 15, f"M8 safe control mutation FPR failure: {m8_safe_pass}/{m8_eligible}"
