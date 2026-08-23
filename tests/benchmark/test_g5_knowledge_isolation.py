"""Unit tests verifying Knowledge Isolation & Classification (INV-G5.4-02 & INV-G5.4-03)."""

from karsasec.benchmark.knowledge_isolation import classify_change


def test_classify_knowledge_only_change() -> None:
    change = {"modified_files": ["benchmarks/k1/development/k1-jwt-001.py"], "added_files": []}
    cls = classify_change(change)
    assert cls == "KNOWLEDGE_ONLY"


def test_classify_engine_change_required() -> None:
    change = {"modified_files": ["karsasec/analysis/taint/engine.py"], "added_files": []}
    cls = classify_change(change)
    assert cls == "ENGINE_CHANGE_REQUIRED"


def test_classify_benchmark_mutation() -> None:
    change = {"modified_files": ["benchmarks/dvwa/manifest.yaml"], "added_files": []}
    cls = classify_change(change)
    assert cls == "BENCHMARK_MUTATION"


def test_classify_evaluator_mutation() -> None:
    change = {"modified_files": ["karsasec/benchmark/independent_evaluator.py"], "added_files": []}
    cls = classify_change(change)
    assert cls == "EVALUATOR_MUTATION"
