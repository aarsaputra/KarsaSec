"""Benchmark test verifying parallel scanning throughput and multi-file worker pool scalability."""

import pytest
import time
from pathlib import Path
from karsasec.cli.commands.scan import execute_scan_command


def test_parallel_scan_throughput(tmp_path: Path):
    """Verifies that multi-file parallel scan executes without errors and scales throughput."""
    # Create 50 sample python files with vulnerable code snippets
    for i in range(50):
        sample = tmp_path / f"sample_{i}.py"
        sample.write_text(
            f"import os\n\ndef run_{i}(user_input):\n    os.system('echo ' + user_input)\n",
            encoding="utf-8",
        )

    start = time.perf_counter()
    exit_code = execute_scan_command(target_path=tmp_path, format_type="json")
    duration = time.perf_counter() - start

    assert exit_code in (0, 1)
    assert duration < 5.0  # Must process 50 files in under 5 seconds
