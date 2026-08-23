"""K1.5 Negative Adversarial Corpus Test Suite (Task K1.5)."""

from pathlib import Path

from karsasec.analysis.taint.k1_integrated import analyze_k1


def test_k1_5_negative_adversarial_corpus_evaluation() -> None:
    neg_dir = Path("benchmarks/k1/adversarial")
    fixtures = sorted(list(neg_dir.glob("*.py")))
    assert len(fixtures) == 20, f"Expected 20 negative adversarial cases, found {len(fixtures)}"

    protected_count = 0
    total_count = len(fixtures)

    for fix_path in fixtures:
        code = fix_path.read_text(encoding="utf-8")
        findings = analyze_k1(code)
        if len(findings) == 0:
            protected_count += 1

    precision = protected_count / total_count
    fpr = (total_count - protected_count) / total_count
    assert precision >= 0.95, f"Negative Adversarial Precision {precision:.4f} below 0.95 threshold ({protected_count}/{total_count})"
    assert fpr <= 0.05, f"Negative Adversarial FPR {fpr:.4f} exceeds 0.05 threshold"
