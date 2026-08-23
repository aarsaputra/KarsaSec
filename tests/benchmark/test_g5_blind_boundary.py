"""Unit tests enforcing Detector Blindness Boundary (INV-G5.3-03)."""

from karsasec.benchmark.blind_runner import BlindDetectorRunner
from karsasec.benchmark.canonical import CanonicalCase


def test_blind_input_isolation() -> None:
    case = CanonicalCase(
        case_id="BENCH_TEST_001",
        source_code="val = request.getParameter('id'); db.execute('SELECT * FROM u WHERE id = ' + val);",
        language="Java",
        framework="Servlet",
        dataset="OWASP_BENCHMARK",
        dataset_version="1.2",
        source_artifact="BenchmarkTest00001.java",
        source_file="org/owasp/benchmark/BenchmarkTest00001.java",
        source_line_start=42,
        source_line_end=50,
        ground_truth_source="OWASP_CSV",
        ground_truth_status="VULNERABLE",
        provenance_sha256="abc123hash",
    )

    blind_input = case.to_blind_input()

    # Assert detector receives ONLY source_code, language, framework
    assert set(blind_input.keys()) == {"source_code", "language", "framework"}
    assert "ground_truth_status" not in blind_input
    assert "case_id" not in blind_input
    assert "dataset" not in blind_input

    # Execute blind runner with extracted blind input
    runner = BlindDetectorRunner()
    res = runner.analyze_blind(**blind_input)

    assert "findings" in res
    assert res["findings"]["SQL_INJECTION"] == "VULNERABLE"
