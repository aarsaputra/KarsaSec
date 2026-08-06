"""Performance benchmark test suite for KarsaSec workspace scanning throughput."""

import time
from pathlib import Path

from karsasec.parser.detector import detect_project


def test_benchmark_1000_files(tmp_path: Path) -> None:
    """Benchmark: Scanning 1,000 synthetic Python files must take < 2.0 seconds."""
    # Generate 1,000 files in 10 directories
    for d in range(10):
        dir_path = tmp_path / f"pkg_{d}"
        dir_path.mkdir(parents=True, exist_ok=True)
        for f in range(100):
            file_path = dir_path / f"module_{f}.py"
            file_path.write_text("import sys\n\ndef run():\n    return 42\n", encoding="utf-8")

    (tmp_path / "requirements.txt").write_text("fastapi\nuvicorn\n", encoding="utf-8")

    start_time = time.perf_counter()
    profile = detect_project(tmp_path)
    elapsed = time.perf_counter() - start_time

    assert profile.total_files >= 1000
    assert "Python" in profile.languages
    assert "FastAPI" in profile.frameworks
    assert elapsed < 2.0, f"Benchmark failed: 1,000 file scan took {elapsed:.3f}s (expected < 2.0s)"
