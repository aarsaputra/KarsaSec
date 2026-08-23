"""Unit tests for path normalization and FindingIdentity stability (E12-2)."""

from __future__ import annotations

from pathlib import Path

from karsasec.qualification.identity import FindingIdentity, _normalize_file, _normalize_path_str
from karsasec.qualification.model import GroundTruthCase, GroundTruthExpectation


class TestNormalization:
    def test_normalize_path_str_variations(self) -> None:
        p1 = _normalize_path_str("vulnerabilities/sqli/source/low.php")
        p2 = _normalize_path_str("./vulnerabilities/sqli/source/low.php")
        p3 = _normalize_path_str("\\vulnerabilities\\sqli\\source\\low.php")
        p4 = _normalize_path_str("/vulnerabilities/sqli/source/low.php")

        assert p1 == "vulnerabilities/sqli/source/low.php"
        assert p1 == p2 == p3 == p4

    def test_normalize_file_relative_to_scan_root(self) -> None:
        scan_root = Path("/tmp/DVWA/vulnerabilities")
        abs_path = Path("/tmp/DVWA/vulnerabilities/sqli/source/low.php")

        norm = _normalize_file(abs_path, scan_root)
        assert norm == "vulnerabilities/sqli/source/low.php"

    def test_identity_matching_equivalence(self) -> None:
        case = GroundTruthCase(
            case_id="c1",
            benchmark="dvwa",
            file="./vulnerabilities/sqli/source/low.php",
            line=10,
            rule_id="KS-PHP-0002",
            expected=GroundTruthExpectation.TRUE_POSITIVE,
            description="test case",
        )
        fi_case = FindingIdentity.from_case(case)

        fi_finding = FindingIdentity(
            normalized_file="vulnerabilities/sqli/source/low.php",
            line=10,
            rule_id="KS-PHP-0002",
        )

        assert fi_case.matches_finding(fi_finding)
        assert fi_case.fingerprint() == fi_finding.fingerprint()
