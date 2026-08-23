"""Unit tests verifying Mutation Oracle Integrity (Phase 1).

Asserts:
1. Baseline verdict is derived from actual detector execution.
2. Mutated verdict is derived from actual detector execution.
3. UNKNOWN -> UNKNOWN transition does NOT kill the mutation.
4. Dynamic verdict transition drives mutation oracle outcome.
"""

from karsasec.benchmark.mutation_runner import RealMutationRunner


def test_mutation_oracle_dynamic_evaluation() -> None:
    runner = RealMutationRunner()

    # Case 1: VULNERABLE -> SAFE (Source Removed) -> KILLED
    suite_killed = [
        {
            "mutation_id": "MUT_AUDIT_001",
            "mutation_type": "SOURCE_REMOVED",
            "original_code": "val = request.getParameter('id'); db.execute('SELECT * FROM u WHERE id = ' + val);",
            "mutated_code": "val = config.get('id'); db.execute('SELECT * FROM u WHERE id = ' + val);",
            "target_property": "SQL_INJECTION",
            "expected_transition": "VULNERABLE->SAFE",
        }
    ]
    res1 = runner.run_mutation_experiment(suite_killed)
    assert res1["results"][0]["baseline_verdict"] == "VULNERABLE"
    assert res1["results"][0]["mutated_verdict"] == "SAFE"
    assert res1["results"][0]["killed"] is True

    # Case 2: UNKNOWN -> UNKNOWN (Unproven code modified to another unproven code) -> SURVIVED
    suite_survived = [
        {
            "mutation_id": "MUT_AUDIT_002",
            "mutation_type": "UNPROVEN_WRAPPER_MODIFY",
            "original_code": "val = unproven_call_1(); sink(val);",
            "mutated_code": "val = unproven_call_2(); sink(val);",
            "target_property": "SQL_INJECTION",
            "expected_transition": "VULNERABLE->SAFE",
        }
    ]
    res2 = runner.run_mutation_experiment(suite_survived)
    assert res2["results"][0]["baseline_verdict"] == "UNKNOWN"
    assert res2["results"][0]["mutated_verdict"] == "UNKNOWN"
    assert res2["results"][0]["killed"] is False
