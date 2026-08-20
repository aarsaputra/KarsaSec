"""Tests for the karsasec qualify CLI command (E12-1)."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

from typer.testing import CliRunner

from karsasec.cli.main import app

runner = CliRunner()


class TestQualifyCLI:
    def test_missing_benchmark_exits_1(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app,
            [
                "qualify",
                "--benchmark",
                "nonexistent_benchmark_xyz",
                "--benchmarks-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code != 0

    def test_valid_benchmark_text_output(self, tmp_path: Path) -> None:
        """E2E: Create a minimal manifest, run qualify --format text."""
        bm_dir = tmp_path / "test_bm"
        bm_dir.mkdir()
        (bm_dir / "manifest.yaml").write_text(
            textwrap.dedent("""
            benchmark:
              id: test_bm
              version: "1.0"
              description: test
            cases:
              - id: t-001
                file: foo.php
                line: 10
                rule_id: KS-PHP-0002
                expected: TRUE_POSITIVE
                description: test case
        """)
        )

        # Create a fake scan target with no PHP files (will produce 0 findings)
        scan_target = tmp_path / "scan_target"
        scan_target.mkdir()

        result = runner.invoke(
            app,
            [
                "qualify",
                "--benchmark",
                "test_bm",
                "--target",
                str(scan_target),
                "--benchmarks-dir",
                str(tmp_path),
                "--format",
                "text",
            ],
        )
        # Should exit 0 (baseline, no pass/fail)
        assert result.exit_code == 0
        assert "Qualification" in result.output or "benchmark" in result.output.lower()

    def test_valid_benchmark_json_output(self, tmp_path: Path) -> None:
        """JSON output must be valid JSON with stable schema."""
        bm_dir = tmp_path / "test_bm"
        bm_dir.mkdir()
        (bm_dir / "manifest.yaml").write_text(
            textwrap.dedent("""
            benchmark:
              id: test_bm
              version: "2.0"
              description: test
            cases:
              - id: t-001
                file: foo.php
                line: 10
                rule_id: KS-PHP-0002
                expected: TRUE_POSITIVE
                description: json test
        """)
        )

        scan_target = tmp_path / "scan_target"
        scan_target.mkdir()

        result = runner.invoke(
            app,
            [
                "qualify",
                "--benchmark",
                "test_bm",
                "--target",
                str(scan_target),
                "--benchmarks-dir",
                str(tmp_path),
                "--format",
                "json",
            ],
        )
        assert result.exit_code == 0
        # Find the JSON in output (may have Rich console output before)
        output = result.output.strip()
        # Try to parse from the last JSON-looking block
        json_start = output.find("{")
        assert json_start >= 0, f"No JSON found in output: {output}"
        doc = json.loads(output[json_start:])
        assert doc["benchmark"] == "test_bm"
        assert "cases" in doc
        assert "metrics" in doc
        assert "findings" in doc
        assert isinstance(doc["metrics"]["precision"], float)
        assert isinstance(doc["metrics"]["recall"], float)
        assert isinstance(doc["metrics"]["f1"], float)

    def test_json_schema_keys_stable(self, tmp_path: Path) -> None:
        """JSON schema must contain all required top-level keys."""
        bm_dir = tmp_path / "schema_bm"
        bm_dir.mkdir()
        (bm_dir / "manifest.yaml").write_text(
            textwrap.dedent("""
            benchmark:
              id: schema_bm
              version: "1.0"
              description: schema test
            cases: []
        """)
        )
        scan_target = tmp_path / "scan_target"
        scan_target.mkdir()

        result = runner.invoke(
            app,
            [
                "qualify",
                "--benchmark",
                "schema_bm",
                "--target",
                str(scan_target),
                "--benchmarks-dir",
                str(tmp_path),
                "--format",
                "json",
            ],
        )
        assert result.exit_code == 0
        output = result.output.strip()
        json_start = output.find("{")
        doc = json.loads(output[json_start:])
        required_keys = {"benchmark", "version", "cases", "metrics", "findings", "per_rule"}
        assert required_keys.issubset(doc.keys()), f"Missing JSON schema keys: {required_keys - doc.keys()}"
        assert set(doc["cases"]) >= {"total", "tp", "fp", "fn", "tn", "unknown"}
        assert set(doc["metrics"]) >= {"precision", "recall", "f1"}
        assert set(doc["findings"]) >= {"raw", "final", "duplicates", "duplicate_rate"}
