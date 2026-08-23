"""K1.5 100-Pass Execution Determinism Test Suite (Task K1.5)."""

from pathlib import Path

from karsasec.analysis.taint.k1_integrated import analyze_k1


def test_k1_5_100_pass_execution_determinism() -> None:
    pos_dir = Path("benchmarks/k1/adversarial_positive")
    fixtures = sorted(list(pos_dir.glob("*.py")))[:5]  # Test sample of 5 adversarial cases

    for fix_path in fixtures:
        code = fix_path.read_text(encoding="utf-8")
        base_res = analyze_k1(code)

        for _ in range(99):
            repeat_res = analyze_k1(code)
            assert base_res == repeat_res, f"Non-deterministic execution on {fix_path.name}"
