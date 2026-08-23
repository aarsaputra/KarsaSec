"""Adversarial Unit Tests for Real Mutation Execution Engine (INVARIANT G5.1-04).

Verifies:
1. Baseline verdict is computed by executing BlindDetectorRunner on original code.
2. Mutated verdict is computed by executing BlindDetectorRunner on mutated code.
3. Mutation kill status is evaluated dynamically based on verdict transition.
4. Mutation score reflects real detector responses.
"""

from karsasec.benchmark.mutation_runner import RealMutationRunner


def test_real_mutation_execution() -> None:
    runner = RealMutationRunner()

    suite = [
        {
            "mutation_id": "MUT_EXEC_001",
            "mutation_type": "SOURCE_REMOVED",
            "original_code": "val = request.getParameter('id'); db.execute('SELECT * FROM u WHERE id = ' + val);",
            "mutated_code": "val = config.get('id'); db.execute('SELECT * FROM u WHERE id = ' + val);",
            "target_property": "SQL_INJECTION",
            "expected_transition": "VULNERABLE->SAFE",
        },
        {
            "mutation_id": "MUT_EXEC_002",
            "mutation_type": "SANITIZER_REMOVED",
            "original_code": "val = request.getParameter('id'); safe = int(val); db.execute('SELECT * FROM u WHERE id = ' + safe);",
            "mutated_code": "val = request.getParameter('id'); db.execute('SELECT * FROM u WHERE id = ' + val);",
            "target_property": "SQL_INJECTION",
            "expected_transition": "SAFE->VULNERABLE",
        },
    ]

    res = runner.run_mutation_experiment(suite)
    assert res["total_mutations"] == 2
    assert res["killed"] == 2
    assert res["mutation_score"] == 1.0
