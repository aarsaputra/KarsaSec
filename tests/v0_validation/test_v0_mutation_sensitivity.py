"""Semantic mutation sensitivity tests for Phase V0."""

from pathlib import Path
from karsasec.validation.v0_corpus_loader import CorpusLoader
from karsasec.validation.v0_mutation_engine import SemanticMutationEngine


def test_semantic_mutation_engine_evaluates_corpus():
    corpus_dir = Path(__file__).resolve().parent.parent / "v0_corpus"
    samples = CorpusLoader.load_from_dir(corpus_dir)
    engine = SemanticMutationEngine()

    score = engine.evaluate_all(samples)
    assert isinstance(score, float)
    assert score >= 80.0, f"Mutation sensitivity score ({score}) below 80.0% threshold"
