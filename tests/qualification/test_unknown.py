"""Unit tests for UNKNOWN confidence isolation and rate metrics (E12-2)."""

from __future__ import annotations

import hashlib
import uuid
from pathlib import Path

from karsasec.core.finding.evidence import Evidence
from karsasec.core.finding.model import Finding
from karsasec.qualification.engine import QualificationEngine
from karsasec.qualification.model import GroundTruthBenchmark, GroundTruthCase, GroundTruthExpectation
from karsasec.rules.enums import Confidence, Severity


def _make_finding(file_path: str, line: int, rule_id: str, confidence: str = "UNKNOWN") -> Finding:
    fp = hashlib.sha256(f"{rule_id}|{file_path}|{line}".encode()).hexdigest()[:32]
    ev = Evidence(
        snippet="test",
        line=line,
        column=1,
    )
    if confidence == "UNKNOWN":
        conf_val = "UNKNOWN"
    elif confidence in (Confidence.CONFIDENT, "HIGH", "CONFIDENT"):
        conf_val = Confidence.CONFIDENT
    elif confidence in (Confidence.LIKELY, "MEDIUM", "LIKELY"):
        conf_val = Confidence.LIKELY
    else:
        conf_val = Confidence.POSSIBLE

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


class TestUnknownIsolation:
    def test_unknown_not_counted_as_tp_or_fp(self) -> None:
        scan_root = Path("/tmp/scan")
        f_unknown = _make_finding("/tmp/scan/low.php", 10, "KS-PHP-0002", confidence="UNKNOWN")

        benchmark = GroundTruthBenchmark(
            benchmark_id="test",
            version="1.0",
            description="test",
            cases=(
                GroundTruthCase(
                    case_id="c1",
                    benchmark="test",
                    file="low.php",
                    line=10,
                    rule_id="KS-PHP-0002",
                    expected=GroundTruthExpectation.TRUE_POSITIVE,
                    description="test",
                ),
            ),
        )

        engine = QualificationEngine()
        result = engine.qualify(
            benchmark=benchmark,
            final_findings=[f_unknown],
            scan_root=scan_root,
            raw_finding_count=1,
            raw_findings=[f_unknown],
        )

        assert result.true_positives == 0
        assert result.false_positives == 0
        assert result.false_negatives == 1
        assert result.unknown_findings == 1
        assert result.unknown_rate == 1.0

    def test_unknown_rate_with_mixed_findings(self) -> None:
        scan_root = Path("/tmp/scan")
        f_high = _make_finding("/tmp/scan/low.php", 10, "KS-PHP-0002", confidence="HIGH")
        f_unknown = _make_finding("/tmp/scan/medium.php", 20, "KS-PHP-0003", confidence="UNKNOWN")

        benchmark = GroundTruthBenchmark(
            benchmark_id="test",
            version="1.0",
            description="test",
            cases=(),
        )

        engine = QualificationEngine()
        result = engine.qualify(
            benchmark=benchmark,
            final_findings=[f_high, f_unknown],
            scan_root=scan_root,
            raw_finding_count=2,
            raw_findings=[f_high, f_unknown],
        )

        assert result.unknown_findings == 1
        assert result.final_findings == 2
        assert result.unknown_rate == 0.5
