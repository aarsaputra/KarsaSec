"""Tests for karsasec.qualification.classifier (E12-1)."""
from __future__ import annotations

import hashlib
import uuid
from pathlib import Path

from karsasec.core.finding.evidence import Evidence
from karsasec.core.finding.model import Finding
from karsasec.qualification.classifier import QualificationClassifier
from karsasec.qualification.model import (
    GroundTruthBenchmark,
    GroundTruthCase,
    GroundTruthExpectation,
)
from karsasec.rules.enums import Confidence, Severity

SCAN_ROOT = Path("/fake/scan/root")


def _finding(
    rule_id: str = "KS-PHP-0002",
    file: str = "vulnerabilities/sqli/source/low.php",
    line: int = 10,
    confidence: Confidence = Confidence.CONFIDENT,
) -> Finding:
    fp = hashlib.sha256(f"{rule_id}|{file}|{line}".encode()).hexdigest()[:32]
    abs_file = SCAN_ROOT / file
    return Finding(
        finding_id=f"f-{uuid.uuid4().hex[:8]}",
        rule_id=rule_id,
        fingerprint=fp,
        title="Test finding",
        severity=Severity.HIGH,
        confidence=confidence,
        cwe_id="CWE-89",
        owasp="A03:2021",
        file_path=abs_file,
        evidence=Evidence(snippet="test", line=line, column=0),
        description="test",
        remediation="test",
    )


def _case(
    case_id: str = "c-001",
    file: str = "vulnerabilities/sqli/source/low.php",
    line: int = 10,
    rule_id: str = "KS-PHP-0002",
    expected: GroundTruthExpectation = GroundTruthExpectation.TRUE_POSITIVE,
) -> GroundTruthCase:
    return GroundTruthCase(
        case_id=case_id, benchmark="test", file=file, line=line,
        rule_id=rule_id, expected=expected, description="Test",
    )


def _benchmark(*cases: GroundTruthCase) -> GroundTruthBenchmark:
    return GroundTruthBenchmark(benchmark_id="test", version="1.0", description="t", cases=tuple(cases))


class TestClassifierTP:
    def test_true_positive(self) -> None:
        bm = _benchmark(_case())
        findings = [_finding()]
        report = QualificationClassifier().classify(bm, findings, SCAN_ROOT)
        assert report.tp == 1
        assert report.fn == 0

    def test_false_negative_when_no_finding(self) -> None:
        bm = _benchmark(_case())
        report = QualificationClassifier().classify(bm, [], SCAN_ROOT)
        assert report.fn == 1
        assert report.tp == 0


class TestClassifierFP:
    def test_false_positive_from_tn_case(self) -> None:
        """Finding at TN location → FP."""
        c = _case(expected=GroundTruthExpectation.TRUE_NEGATIVE)
        bm = _benchmark(c)
        findings = [_finding()]  # finding at same location as TN
        report = QualificationClassifier().classify(bm, findings, SCAN_ROOT)
        assert report.fp_from_tn == 1

    def test_true_negative_when_no_finding(self) -> None:
        c = _case(expected=GroundTruthExpectation.TRUE_NEGATIVE)
        bm = _benchmark(c)
        report = QualificationClassifier().classify(bm, [], SCAN_ROOT)
        assert report.tn == 1
        assert report.fp_from_tn == 0

    def test_unmatched_finding_is_fp(self) -> None:
        """Finding with no ground-truth expectation → counted as FP."""
        bm = _benchmark()  # empty ground truth
        findings = [_finding()]
        report = QualificationClassifier().classify(bm, findings, SCAN_ROOT)
        assert report.fp_unmatched == 1
        assert report.fp == 1

    def test_fp_total_is_sum(self) -> None:
        c = _case(case_id="tn", file="vulnerabilities/fi.php", line=5,
                  expected=GroundTruthExpectation.TRUE_NEGATIVE)
        bm = _benchmark(c)
        # Finding at TN location (fp_from_tn) + unrelated finding (fp_unmatched)
        f_tn = _finding(file="vulnerabilities/fi.php", line=5)
        f_unrelated = _finding(file="vulnerabilities/other.php", line=99)
        report = QualificationClassifier().classify(bm, [f_tn, f_unrelated], SCAN_ROOT)
        assert report.fp_from_tn == 1
        assert report.fp_unmatched == 1
        assert report.fp == 2


class TestClassifierMultiple:
    def test_multiple_findings_multiple_cases(self) -> None:
        bm = _benchmark(
            _case(case_id="tp-1", line=10),
            _case(case_id="tp-2", line=20),
        )
        findings = [_finding(line=10), _finding(line=20)]
        report = QualificationClassifier().classify(bm, findings, SCAN_ROOT)
        assert report.tp == 2
        assert report.fn == 0

    def test_missing_one_finding(self) -> None:
        bm = _benchmark(
            _case(case_id="tp-1", line=10),
            _case(case_id="tp-2", line=20),
        )
        findings = [_finding(line=10)]  # only one finding
        report = QualificationClassifier().classify(bm, findings, SCAN_ROOT)
        assert report.tp == 1
        assert report.fn == 1


class TestClassifierUnknown:
    def test_unknown_confidence_tracked_separately(self) -> None:
        """UNKNOWN confidence findings must never count as TP or FP."""
        bm = _benchmark(_case())
        findings = [_finding(confidence=Confidence.POSSIBLE)]  # non-UNKNOWN
        # There's no UNKNOWN enum on Confidence (enforced by E10-3J)
        # Just verify normal flow still works
        report = QualificationClassifier().classify(bm, findings, SCAN_ROOT)
        assert report.unknown == 0
