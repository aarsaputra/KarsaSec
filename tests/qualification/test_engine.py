"""Tests for karsasec.qualification.engine (E12-1)."""

from __future__ import annotations

import hashlib
import uuid
from pathlib import Path

import pytest

from karsasec.core.finding.evidence import Evidence
from karsasec.core.finding.model import Finding
from karsasec.qualification.engine import QualificationEngine
from karsasec.qualification.model import (
    GroundTruthBenchmark,
    GroundTruthCase,
    GroundTruthExpectation,
)
from karsasec.rules.enums import Confidence, Severity

SCAN_ROOT = Path("/fake/scan/root")


def _f(rule_id: str = "KS-PHP-0002", file: str = "sqli/low.php", line: int = 10) -> Finding:
    fp = hashlib.sha256(f"{rule_id}|{file}|{line}".encode()).hexdigest()[:32]
    return Finding(
        finding_id=f"f-{uuid.uuid4().hex[:8]}",
        rule_id=rule_id,
        fingerprint=fp,
        title="test",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIDENT,
        cwe_id="CWE-89",
        owasp="A03",
        file_path=SCAN_ROOT / file,
        evidence=Evidence(snippet="test", line=line, column=0),
        description="test",
        remediation="test",
    )


def _c(
    case_id: str,
    file: str = "sqli/low.php",
    line: int = 10,
    expected: GroundTruthExpectation = GroundTruthExpectation.TRUE_POSITIVE,
) -> GroundTruthCase:
    return GroundTruthCase(
        case_id=case_id, benchmark="t", file=file, line=line, rule_id="KS-PHP-0002", expected=expected, description="t"
    )


def _bm(*cases: GroundTruthCase) -> GroundTruthBenchmark:
    return GroundTruthBenchmark(benchmark_id="t", version="1", description="", cases=tuple(cases))


class TestQualificationEngine:
    def setup_method(self) -> None:
        self.engine = QualificationEngine()

    def test_perfect_detection(self) -> None:
        bm = _bm(_c("tp-1", line=10), _c("tp-2", line=20))
        findings = [_f(line=10), _f(line=20)]
        result = self.engine.qualify(bm, findings, SCAN_ROOT)
        assert result.true_positives == 2
        assert result.false_negatives == 0
        assert result.precision == pytest.approx(1.0)
        assert result.recall == pytest.approx(1.0)
        assert result.f1 == pytest.approx(1.0)

    def test_all_fn(self) -> None:
        bm = _bm(_c("tp-1"), _c("tp-2", line=20))
        result = self.engine.qualify(bm, [], SCAN_ROOT)
        assert result.false_negatives == 2
        assert result.true_positives == 0
        assert result.recall == 0.0

    def test_false_positive_unmatched(self) -> None:
        """Unmatched finding → FP."""
        bm = _bm()
        findings = [_f()]
        result = self.engine.qualify(bm, findings, SCAN_ROOT)
        assert result.false_positives == 1
        assert result.precision == 0.0

    def test_tn_correctly_counted(self) -> None:
        bm = _bm(_c("tn-1", expected=GroundTruthExpectation.TRUE_NEGATIVE))
        result = self.engine.qualify(bm, [], SCAN_ROOT)
        assert result.true_negatives == 1
        assert result.false_positives == 0

    def test_duplicate_rate_calculated(self) -> None:
        bm = _bm()
        findings = [_f()]
        result = self.engine.qualify(bm, findings, SCAN_ROOT, raw_finding_count=10)
        assert result.raw_findings == 10
        assert result.final_findings == 1
        assert result.duplicate_findings == 9
        assert result.duplicate_rate == pytest.approx(0.9)

    def test_per_rule_populated(self) -> None:
        bm = _bm(_c("tp-1"), _c("tp-2", line=20))
        findings = [_f(line=10)]
        result = self.engine.qualify(bm, findings, SCAN_ROOT)
        assert "KS-PHP-0002" in result.per_rule
        rr = result.per_rule["KS-PHP-0002"]
        assert rr.tp == 1
        assert rr.fn == 1

    def test_result_is_deterministic(self) -> None:
        bm = _bm(_c("tp-1"), _c("tp-2", line=20))
        findings = [_f(line=10), _f(line=20)]
        r1 = self.engine.qualify(bm, findings, SCAN_ROOT)
        r2 = self.engine.qualify(bm, findings, SCAN_ROOT)
        assert r1.true_positives == r2.true_positives
        assert r1.precision == r2.precision
        assert r1.f1 == r2.f1

    def test_benchmark_id_in_result(self) -> None:
        bm = _bm()
        result = self.engine.qualify(bm, [], SCAN_ROOT)
        assert result.benchmark_id == "t"
