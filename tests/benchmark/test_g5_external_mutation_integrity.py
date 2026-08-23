"""Adversarial unit tests for Mutation Oracle Integrity (Phase 7).

Verifies:
1. Baseline decision vs. mutated decision drives mutation oracle outcome.
2. UNKNOWN -> UNKNOWN transition strictly evaluates to SURVIVED.
3. SAFE -> SAFE transition strictly evaluates to SURVIVED.
4. Expected transition metadata cannot force a kill if detector verdicts do not change.
"""

from karsasec.benchmark.mutation_runner import RealMutationRunner


def test_mutation_oracle_unknown_survival() -> None:
    runner = RealMutationRunner()

    suite = [
        {
            "mutation_id": "MUT_ADV_001",
            "mutation_type": "UNPROVEN_RENAME",
            "original_code": "val = unproven_func_a(); sink(val);",
            "mutated_code": "val = unproven_func_b(); sink(val);",
            "target_property": "SQL_INJECTION",
            "expected_transition": "VULNERABLE->SAFE",
        }
    ]

    res = runner.run_mutation_experiment(suite)
    item = res["results"][0]
    assert item["baseline_verdict"] == "UNKNOWN"
    assert item["mutated_verdict"] == "UNKNOWN"
    # UNKNOWN -> UNKNOWN MUST evaluate to SURVIVED
    assert item["killed"] is False
    assert item["status"] == "SURVIVED"
