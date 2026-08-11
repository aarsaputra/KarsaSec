"""Tests for karsasec.qualification.model (E12-1)."""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from karsasec.qualification.model import (
    GroundTruthBenchmark,
    GroundTruthCase,
    GroundTruthExpectation,
    ManifestLoader,
)


def _case(**kw) -> GroundTruthCase:
    defaults = dict(case_id="t-001", benchmark="test", file="foo.php", line=10,
                    rule_id="KS-PHP-0002", expected=GroundTruthExpectation.TRUE_POSITIVE,
                    description="Test case")
    defaults.update(kw)
    return GroundTruthCase(**defaults)


class TestGroundTruthCase:
    def test_valid_case(self) -> None:
        c = _case()
        assert c.case_id == "t-001"
        assert c.expected == GroundTruthExpectation.TRUE_POSITIVE

    def test_empty_case_id_raises(self) -> None:
        with pytest.raises(ValueError, match="case_id"):
            _case(case_id="")

    def test_empty_description_raises(self) -> None:
        with pytest.raises(ValueError, match="description"):
            _case(description="")

    def test_line_zero_raises(self) -> None:
        with pytest.raises(ValueError, match="line"):
            _case(line=0)

    def test_line_none_is_ok(self) -> None:
        c = _case(line=None)
        assert c.line is None

    def test_tn_expectation(self) -> None:
        c = _case(expected=GroundTruthExpectation.TRUE_NEGATIVE)
        assert c.expected == GroundTruthExpectation.TRUE_NEGATIVE


class TestGroundTruthBenchmark:
    def test_valid_benchmark(self) -> None:
        cases = (
            _case(case_id="a-001"),
            _case(case_id="a-002", expected=GroundTruthExpectation.TRUE_NEGATIVE),
        )
        bm = GroundTruthBenchmark(benchmark_id="test", version="1.0", description="t", cases=cases)
        assert bm.benchmark_id == "test"
        assert len(bm.cases) == 2

    def test_duplicate_case_id_raises(self) -> None:
        cases = (_case(case_id="dup"), _case(case_id="dup"))
        with pytest.raises(ValueError, match="Duplicate case_id"):
            GroundTruthBenchmark(benchmark_id="test", version="1.0", description="t", cases=cases)

    def test_tp_tn_partition(self) -> None:
        cases = (
            _case(case_id="tp-1", expected=GroundTruthExpectation.TRUE_POSITIVE),
            _case(case_id="tn-1", expected=GroundTruthExpectation.TRUE_NEGATIVE),
        )
        bm = GroundTruthBenchmark(benchmark_id="x", version="1", description="", cases=cases)
        assert len(bm.tp_cases) == 1
        assert len(bm.tn_cases) == 1

    def test_rules_covered(self) -> None:
        cases = (
            _case(case_id="a", rule_id="KS-PHP-0002"),
            _case(case_id="b", rule_id="KS-PHP-0003"),
        )
        bm = GroundTruthBenchmark(benchmark_id="x", version="1", description="", cases=cases)
        assert bm.rules_covered == frozenset({"KS-PHP-0002", "KS-PHP-0003"})


class TestManifestLoader:
    def _write_yaml(self, tmp_path: Path, content: str) -> Path:
        p = tmp_path / "manifest.yaml"
        p.write_text(textwrap.dedent(content))
        return p

    def test_valid_manifest(self, tmp_path: Path) -> None:
        p = self._write_yaml(tmp_path, """
            benchmark:
              id: test
              version: "1.0"
              description: test
            cases:
              - id: t-001
                file: foo.php
                line: 10
                rule_id: KS-PHP-0002
                expected: TRUE_POSITIVE
                description: A test case
        """)
        bm = ManifestLoader().load(p)
        assert bm.benchmark_id == "test"
        assert len(bm.cases) == 1

    def test_missing_id_raises(self, tmp_path: Path) -> None:
        p = self._write_yaml(tmp_path, """
            benchmark:
              version: "1.0"
              description: missing id
            cases: []
        """)
        with pytest.raises(ValueError, match="benchmark.id"):
            ManifestLoader().load(p)

    def test_invalid_expected_raises(self, tmp_path: Path) -> None:
        p = self._write_yaml(tmp_path, """
            benchmark:
              id: test
              version: "1.0"
              description: x
            cases:
              - id: t-001
                file: foo.php
                line: 10
                rule_id: KS-PHP-0002
                expected: INVALID_VALUE
                description: bad
        """)
        with pytest.raises(ValueError, match="invalid 'expected'"):
            ManifestLoader().load(p)

    def test_missing_description_raises(self, tmp_path: Path) -> None:
        p = self._write_yaml(tmp_path, """
            benchmark:
              id: test
              version: "1.0"
              description: x
            cases:
              - id: t-001
                file: foo.php
                line: 10
                rule_id: KS-PHP-0002
                expected: TRUE_POSITIVE
        """)
        with pytest.raises(ValueError, match="description"):
            ManifestLoader().load(p)

    def test_duplicate_case_ids_raises(self, tmp_path: Path) -> None:
        p = self._write_yaml(tmp_path, """
            benchmark:
              id: test
              version: "1.0"
              description: x
            cases:
              - id: dup-001
                file: foo.php
                line: 10
                rule_id: KS-PHP-0002
                expected: TRUE_POSITIVE
                description: first
              - id: dup-001
                file: bar.php
                line: 20
                rule_id: KS-PHP-0002
                expected: TRUE_POSITIVE
                description: second
        """)
        with pytest.raises(ValueError, match="Duplicate case_id"):
            ManifestLoader().load(p)

    def test_nonexistent_manifest_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            ManifestLoader().load(tmp_path / "nonexistent.yaml")

    def test_malformed_yaml_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "manifest.yaml"
        p.write_text("benchmark:\n  id: [unclosed")
        with pytest.raises(ValueError, match="YAML"):
            ManifestLoader().load(p)
