"""Unit tests for exact duplicate findings and cross-rule overlap detection (E12-2)."""
from __future__ import annotations

import hashlib
import uuid
from pathlib import Path

import pytest

from karsasec.core.finding.evidence import Evidence
from karsasec.core.finding.model import Finding
from karsasec.qualification.engine import QualificationEngine
from karsasec.qualification.model import GroundTruthBenchmark, GroundTruthCase, GroundTruthExpectation
from karsasec.rules.enums import Confidence, Severity


def _make_finding(file_path: str, line: int, rule_id: str, confidence: str | Confidence = Confidence.CONFIDENT) -> Finding:
    fp = hashlib.sha256(f"{rule_id}|{file_path}|{line}".encode()).hexdigest()[:32]
    ev = Evidence(
        snippet="test",
        line=line,
        column=1,
    )
    conf_val = confidence if isinstance(confidence, Confidence) else Confidence(confidence)
    return Finding(
        finding_id=f"f-{uuid.uuid4().hex[:8]}",
        rule_id=rule_id,
        fingerprint=fp,
        title="Test finding",
        severity=Severity.HIGH,
        confidence=conf_val,
        cwe_id="CWE-89",
        owasp="A03:2021",
        file_path=Path(file_path),
        evidence=ev,
        description="test",
        remediation="test",
    )


class TestDuplicatesAndOverlaps:

    def test_exact_duplicates(self) -> None:
        scan_root = Path("/tmp/scan")
        f1 = _make_finding("/tmp/scan/low.php", 10, "KS-PHP-0002")
        f2 = _make_finding("/tmp/scan/low.php", 10, "KS-PHP-0002")
        f3 = _make_finding("/tmp/scan/low.php", 10, "KS-PHP-0002")

        benchmark = GroundTruthBenchmark(
            benchmark_id="test",
            version="1.0",
            description="test",
            cases=(
                GroundTruthCase(
                    case_id="c1", benchmark="test", file="low.php", line=10,
                    rule_id="KS-PHP-0002", expected=GroundTruthExpectation.TRUE_POSITIVE,
                    description="test",
                ),
            ),
        )

        engine = QualificationEngine()
        result = engine.qualify(
            benchmark=benchmark,
            final_findings=[f1],
            scan_root=scan_root,
            raw_finding_count=3,
            raw_findings=[f1, f2, f3],
        )

        assert result.raw_findings == 3
        assert result.final_findings == 1
        assert result.exact_duplicates == 2
        assert pytest.approx(result.exact_duplicate_rate, 0.001) == 2 / 3

    def test_cross_rule_overlap(self) -> None:
        scan_root = Path("/tmp/scan")
        f1 = _make_finding("/tmp/scan/view_help.php", 20, "KS-OWASP-0010")
        f2 = _make_finding("/tmp/scan/view_help.php", 20, "KS-PHP-0003")
        f3 = _make_finding("/tmp/scan/view_help.php", 20, "KS-PHP-SSRF-0001")

        benchmark = GroundTruthBenchmark(
            benchmark_id="test",
            version="1.0",
            description="test",
            cases=(),
        )

        engine = QualificationEngine()
        result = engine.qualify(
            benchmark=benchmark,
            final_findings=[f1, f2, f3],
            scan_root=scan_root,
            raw_finding_count=3,
            raw_findings=[f1, f2, f3],
        )

        assert result.cross_rule_overlaps == 1
        assert result.cross_rule_overlap_rate == 1.0
