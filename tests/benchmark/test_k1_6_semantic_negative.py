"""K1.6 Complex Safe-Control Semantic Negative Test Suite.

Verifies INV-K1.6-06: Evaluates False Positive Rate across benchmarks/k1/adversarial_semantic_negative/.
"""

from pathlib import Path

from karsasec.analysis.taint.k1_integrated import analyze_k1


def test_k1_6_semantic_negative_adversarial_fpr() -> None:
    sem_neg_dir = Path("benchmarks/k1/adversarial_semantic_negative")
    fixtures = sorted(list(sem_neg_dir.glob("*.py")))
    assert len(fixtures) == 15, f"Expected 15 semantic negative fixtures, found {len(fixtures)}"

    fp_count = 0
    total_count = len(fixtures)

    for fix_path in fixtures:
        code = fix_path.read_text(encoding="utf-8")
        findings = analyze_k1(code)
        if len(findings) > 0:
            fp_count += 1
            print(f"Semantic Negative FP in {fix_path.name}: {findings}")

    fpr = fp_count / total_count
    assert (
        fpr == 0.0
    ), f"Semantic Negative FPR is {fpr:.4f} ({fp_count}/{total_count} False Positives)! Expected 0.0"
