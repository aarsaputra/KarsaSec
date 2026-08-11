"""Unit tests for CanonicalFindingIdentity and path normalization (E12-4)."""

from pathlib import Path

from karsasec.core.finding.evidence import Evidence
from karsasec.core.finding.model import CanonicalFindingIdentity, Finding, normalize_finding_path
from karsasec.rules.enums import Confidence, Severity


def test_normalize_finding_path() -> None:
    p1 = Path("vulnerabilities\\sqli\\source\\low.php")
    assert normalize_finding_path(p1) == "vulnerabilities/sqli/source/low.php"

    p2 = Path("./vulnerabilities/./exec/../sqli/source/low.php")
    assert normalize_finding_path(p2) == "vulnerabilities/sqli/source/low.php"


def test_canonical_finding_identity_exact_and_semantic() -> None:
    ident1 = CanonicalFindingIdentity.create(
        file_path="app/views.php",
        line=42,
        rule_id="KS-OWASP-0001",
        snippet="pg_query($db, $sql)",
        sink_category="SQL_EXECUTION",
        sink_symbol="pg_query",
        taint_path_hops=("$_GET['id']", "$sql"),
        cwe_id="CWE-89",
    )

    ident2 = CanonicalFindingIdentity.create(
        file_path="app/views.php",
        line=42,
        rule_id="KS-PHP-SQLI-0002",  # Different rule!
        snippet="pg_query($db, $sql)",
        sink_category="SQL_EXECUTION",
        sink_symbol="pg_query",
        taint_path_hops=("$_GET['id']", "$sql"),
        cwe_id="CWE-89",
    )

    # Exact keys must differ because rule_ids differ
    assert ident1.exact_key != ident2.exact_key

    # Semantic keys must match because sink, line, path, and file match!
    assert ident1.semantic_key == ident2.semantic_key


def test_canonical_finding_identity_from_finding() -> None:
    f = Finding(
        finding_id="f-101",
        rule_id="KS-OWASP-0010",
        fingerprint="fp123",
        title="Command Injection",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIDENT,
        cwe_id="CWE-78",
        owasp="A03:2021-Injection",
        file_path=Path("vulnerabilities/exec/source/low.php"),
        evidence=Evidence(snippet="system($cmd)", line=12, column=1),
        description="Cmd injection",
        remediation="Sanitize",
    )

    ident = CanonicalFindingIdentity.from_finding(f)
    assert ident.normalized_file == "vulnerabilities/exec/source/low.php"
    assert ident.line == 12
    assert ident.rule_id == "KS-OWASP-0010"
