"""K1.5 Positive Adversarial Corpus Test Suite (Task K1.5)."""

from pathlib import Path

from karsasec.analysis.taint.k1_integrated import analyze_k1


def test_k1_5_positive_adversarial_corpus_evaluation() -> None:
    pos_dir = Path("benchmarks/k1/adversarial_positive")
    fixtures = sorted(list(pos_dir.glob("*.py")))
    assert len(fixtures) == 20, f"Expected 20 positive adversarial cases, found {len(fixtures)}"

    detected_count = 0
    total_count = len(fixtures)

    for fix_path in fixtures:
        code = fix_path.read_text(encoding="utf-8")
        findings = analyze_k1(code)
        if len(findings) > 0:
            detected_count += 1

    recall = detected_count / total_count
    assert recall >= 0.95, f"Positive Adversarial Recall {recall:.4f} below 0.95 threshold ({detected_count}/{total_count})"
