"""Pass/Fail Gate and KPI Scorecard tests for Phase V0."""

from pathlib import Path
from karsasec.validation.v0_corpus_loader import CorpusLoader
from karsasec.validation.v0_evaluator import GroundTruthEvaluator
from karsasec.validation.v0_mutation_engine import SemanticMutationEngine
from karsasec.validation.v0_scorecard import ScorecardEngine


def test_v0_scorecard_generation_and_gate_evaluation():
    corpus_dir = Path(__file__).resolve().parent.parent / "v0_corpus"
    samples = CorpusLoader.load_from_dir(corpus_dir)
    evaluator = GroundTruthEvaluator()
    mutation_engine = SemanticMutationEngine(evaluator=evaluator)

    results = [evaluator.evaluate_sample(s) for s in samples]
    mutation_score = mutation_engine.evaluate_all(samples)

    scorecard = ScorecardEngine.generate_scorecard(results, mutation_sensitivity_score=mutation_score)

    assert scorecard.total_samples == len(samples)
    assert scorecard.gate_status in ("PASS", "FAIL")
