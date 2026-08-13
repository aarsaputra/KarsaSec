"""Unit tests for SecurityArtifactReader (E13-1)."""

from __future__ import annotations

from pathlib import Path

from karsasec.ai.artifacts import SecurityArtifactReader
from karsasec.core.finding.evidence import Evidence
from karsasec.core.finding.model import Finding
from karsasec.graph.dataflow.security_verdict import DecisionReason, SecurityVerdict, VerdictConfidence, VerdictStatus
from karsasec.rules.enums import Confidence, Severity


def _create_sample_finding(finding_id: str = "F-001", verdict: SecurityVerdict | None = None) -> Finding:
    return Finding(
        finding_id=finding_id,
        rule_id="RULE-SQLI",
        fingerprint="fp1234567890abcdef",
        title="SQL Injection Vulnerability",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe_id="CWE-89",
        owasp="A03:2021-Injection",
        file_path=Path("app/db.py"),
        evidence=Evidence(snippet="query = f'SELECT * FROM users WHERE id = {user_id}'", line=15, column=4),
        description="Unsanitized user input reaches SQL query execution sink.",
        remediation="Use parameterized queries.",
        verdict=verdict,
    )


def test_artifact_reader_from_findings() -> None:
    finding = _create_sample_finding("F-101")
    reader = SecurityArtifactReader.from_findings([finding])

    findings = reader.get_findings()
    assert len(findings) == 1
    assert reader.get_finding("F-101") == finding
    assert reader.get_finding("F-MISSING") is None


def test_artifact_reader_get_verdict() -> None:
    verdict = SecurityVerdict.create(
        status=VerdictStatus.VULNERABLE,
        confidence=VerdictConfidence.HIGH,
        rule_id="RULE-SQLI",
        sink_id="sink_query",
        sink_category="SQL_EXECUTION",
        file_path="app/db.py",
        function_name="get_user",
        line_number=15,
        variable_version="$user_id#1",
        reason_codes=(DecisionReason.TAINT_REACHES_SINK,),
        provenance_path=("src/route.py:5", "app/db.py:15"),
    )

    finding = _create_sample_finding("F-101", verdict=verdict)
    reader = SecurityArtifactReader.from_findings([finding])

    extracted_verdict = reader.get_verdict("F-101")
    assert extracted_verdict == verdict
    assert extracted_verdict.status == VerdictStatus.VULNERABLE


def test_artifact_reader_get_evidence() -> None:
    finding = _create_sample_finding("F-101")
    reader = SecurityArtifactReader.from_findings([finding])

    ev = reader.get_evidence("F-101")
    assert ev is not None
    assert ev.line == 15
    assert "user_id" in ev.snippet


def test_artifact_reader_provenance() -> None:
    verdict = SecurityVerdict.create(
        status=VerdictStatus.VULNERABLE,
        confidence=VerdictConfidence.HIGH,
        rule_id="RULE-SQLI",
        sink_id="sink_query",
        sink_category="SQL_EXECUTION",
        file_path="app/db.py",
        function_name="get_user",
        line_number=15,
        variable_version="$user_id#1",
        reason_codes=(DecisionReason.TAINT_REACHES_SINK,),
        provenance_path=("src/route.py:5", "app/db.py:15"),
    )
    finding = _create_sample_finding("F-101", verdict=verdict)
    reader = SecurityArtifactReader.from_findings([finding])

    prov = reader.get_provenance("F-101")
    assert prov == ("src/route.py:5", "app/db.py:15")


def test_artifact_reader_source_snippet() -> None:
    finding = _create_sample_finding("F-101")
    reader = SecurityArtifactReader.from_findings([finding])

    snippet = reader.get_source_snippet("F-101")
    assert snippet == "query = f'SELECT * FROM users WHERE id = {user_id}'"
    assert reader.get_source_snippet("NON_EXISTENT") == "UNKNOWN"
