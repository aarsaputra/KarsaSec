"""Gate 5 Master Runner Integration Tests.

Verifies:
1. Full execution of Phase G5-1 (Readiness) -> G5-2 (Baseline) -> G5-3 (Forensics) -> G5-4 (Mutation)
2. Generation of per-test-case JSON and immutable result files in benchmark_results/owasp/<run_id>/
3. ASCII report generation matching Chief Architect Directive schema
"""

from pathlib import Path

from karsasec.benchmark.runner import MasterGate5Runner


def test_master_gate_5_runner_execution(tmp_path: Path) -> None:
    runner = MasterGate5Runner(output_dir=str(tmp_path))
    res = runner.run_full_gate_5()

    assert "run_dir" in res
    run_dir = Path(res["run_dir"])
    assert run_dir.exists()

    assert (run_dir / "readiness_manifest.json").exists()
    assert (run_dir / "raw_predictions.json").exists()
    assert (run_dir / "ground_truth.json").exists()
    assert (run_dir / "metrics.json").exists()
    assert (run_dir / "per_test_case_results.json").exists()
    assert (run_dir / "error_forensics.json").exists()
    assert (run_dir / "mutation_results.json").exists()
    assert (run_dir / "report.md").exists()

    report_content = (run_dir / "report.md").read_text(encoding="utf-8")
    assert "KARSASEC G5" in report_content
    assert "MULTI-FRAMEWORK MATRIX" in report_content
    assert "ERROR FORENSICS & TAXONOMY" in report_content
    assert "MUTATION HARDENING RESULTS" in report_content
    assert "ARCHITECTURAL VERDICT" in report_content
