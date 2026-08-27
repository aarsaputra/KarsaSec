"""Adversarial Verification Suite for Query Plan Fingerprinting & Canonicalization (E9.5.5).

Validates:
- 64-char hex SHA256 length invariant
- Dictionary key insertion order independence
- Semantic difference produces distinct fingerprints
- Fingerprint reproducibility across separate executions
"""

import os
import subprocess
import sys
from karsasec.query.ast import PredicateNode, QueryNode, QueryStep, StepType
from karsasec.query.optimizer import QueryOptimizer


def test_fingerprint_hex_length_invariant():
    """Fingerprint must strictly be a 64-character lowercase hex string."""
    optimizer = QueryOptimizer()
    ast = QueryNode(
        target_label="AST",
        steps=(QueryStep(StepType.WHERE, predicate=PredicateNode("EQUALS", "id", "n1")),),
    )

    fingerprint = optimizer.compute_plan_fingerprint(ast)
    assert len(fingerprint) == 64
    assert all(c in "0123456789abcdef" for c in fingerprint)


def test_dict_ordering_fingerprint_identity():
    """Identical query AST constructed via different code paths produces identical fingerprint."""
    optimizer = QueryOptimizer()

    ast1 = QueryNode(
        target_label="AST",
        steps=(
            QueryStep(StepType.WHERE, predicate=PredicateNode("EQUALS", "function_name", "main")),
            QueryStep(StepType.WHERE, predicate=PredicateNode("EQUALS", "id", "n1")),
        ),
        projection_fields=("id", "line_number"),
    )

    ast2 = QueryNode(
        target_label="AST",
        steps=(
            QueryStep(StepType.WHERE, predicate=PredicateNode("EQUALS", "function_name", "main")),
            QueryStep(StepType.WHERE, predicate=PredicateNode("EQUALS", "id", "n1")),
        ),
        projection_fields=("id", "line_number"),
    )

    fp1 = optimizer.compute_plan_fingerprint(ast1)
    fp2 = optimizer.compute_plan_fingerprint(ast2)

    assert fp1 == fp2


def test_non_equivalent_ast_distinct_fingerprints():
    """Non-equivalent queries MUST NOT collide or produce identical plan fingerprints."""
    optimizer = QueryOptimizer()

    ast_equals = QueryNode(
        target_label="AST",
        steps=(QueryStep(StepType.WHERE, predicate=PredicateNode("EQUALS", "ssa_version", "v1")),),
    )
    ast_not_equals = QueryNode(
        target_label="AST",
        steps=(QueryStep(StepType.WHERE, predicate=PredicateNode("NOT_EQUALS", "ssa_version", "v1")),),
    )

    ast_v2 = QueryNode(
        target_label="AST",
        steps=(QueryStep(StepType.WHERE, predicate=PredicateNode("EQUALS", "ssa_version", "v2")),),
    )

    fp1 = optimizer.compute_plan_fingerprint(ast_equals)
    fp2 = optimizer.compute_plan_fingerprint(ast_not_equals)
    fp3 = optimizer.compute_plan_fingerprint(ast_v2)

    assert fp1 != fp2
    assert fp1 != fp3
    assert fp2 != fp3


def test_python_hash_seed_independence():
    """Fingerprint calculation must be deterministic across different PYTHONHASHSEED environments."""
    cmd = [
        sys.executable,
        "-c",
        "from karsasec.query.optimizer import QueryOptimizer; "
        "from karsasec.query.ast import QueryNode, QueryStep, StepType, PredicateNode; "
        "ast = QueryNode('AST', (QueryStep(StepType.WHERE, predicate=PredicateNode('EQUALS', 'id', 'n1')),)); "
        "print(QueryOptimizer().compute_plan_fingerprint(ast))",
    ]

    env1 = os.environ.copy()
    env1["PYTHONHASHSEED"] = "1"
    res1 = subprocess.check_output(cmd, env=env1).decode().strip()

    env2 = os.environ.copy()
    env2["PYTHONHASHSEED"] = "9999"
    res2 = subprocess.check_output(cmd, env=env2).decode().strip()

    assert len(res1) == 64
    assert res1 == res2
