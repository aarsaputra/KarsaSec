"""Real-world benchmark evaluation tests for Phase V0 against E9->E16 foundation engine."""

from pathlib import Path
from karsasec.validation.v0_corpus_loader import CorpusLoader
from karsasec.validation.v0_evaluator import GroundTruthEvaluator


def test_evaluator_runs_all_corpus_samples():
    corpus_dir = Path(__file__).resolve().parent.parent / "v0_corpus"
    samples = CorpusLoader.load_from_dir(corpus_dir)
    evaluator = GroundTruthEvaluator()

    for sample in samples:
        res = evaluator.evaluate_sample(sample)
        assert res.sample_id == sample.sample_id
        assert res.actual_decision in ("ALLOW", "BLOCK", "REVIEW", "UNKNOWN")
        assert res.actual_admission in ("APPROVED", "BLOCKED", "REVIEW_REQUIRED", "UNKNOWN")
