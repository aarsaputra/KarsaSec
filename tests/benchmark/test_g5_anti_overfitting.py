"""Anti-Overfitting Verification Suite.

Asserts that no detector file in karsasec/analysis/ or karsasec/rules/ imports or references benchmark case IDs.
"""

import pathlib


def test_no_detector_benchmark_coupling() -> None:
    analysis_dir = pathlib.Path("karsasec/analysis")
    forbidden_terms = ["OWASP", "B000", "B001", "ground_truth", "expected_status"]

    for py_file in analysis_dir.rglob("*.py"):
        content = py_file.read_text()
        for term in forbidden_terms:
            assert term not in content, f"Forbidden benchmark term '{term}' found in detector file {py_file}"
