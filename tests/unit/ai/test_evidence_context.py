"""Unit tests for SecurityFindingContextBuilder (E13-1)."""

from __future__ import annotations

from pathlib import Path

from karsasec.ai.evidence_context import SecurityFindingContextBuilder
from karsasec.core.finding.evidence import Evidence, FindingEvidence
from karsasec.core.finding.model import Finding, QualifiedFinding, QualificationState
from karsasec.graph.dataflow.security_verdict import DecisionReason, SecurityVerdict, VerdictConfidence, VerdictStatus
from karsasec.rules.enums import Confidence, Severity


def test_context_builder_full_finding() -> None:
    verdict = SecurityVerdict.create(
        status=VerdictStatus.VULNERABLE,
        confidence=VerdictConfidence.HIGH,
        rule_id="RULE-XSS",
        sink_id="sink_echo",
        sink_category="XSS_SINK",
        file_path="views/profile.php",
        function_name="render",
        line_number=42,
        variable_version="$name#2",
        call_context="ctx_req_1",
        branch_polarity="TRUE",
        reason_codes=(DecisionReason.TAINT_REACHES_SINK, DecisionReason.GUARD_NOT_PROVEN),
        provenance_path=("index.php:10", "views/profile.php:42"),
    )

    finding = Finding(
        finding_id="F-201",
        rule_id="RULE-XSS",
        fingerprint="fp_profile_xss",
        title="Reflected XSS",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe_id="CWE-79",
        owasp="A03:2021-Injection",
        file_path=Path("views/profile.php"),
        evidence=Evidence(snippet="echo $_GET['name'];", line=42, column=1),
        description="User input rendered directly to response stream.",
        remediation="Apply htmlspecialchars.",
        verdict=verdict,
    )

    ctx = SecurityFindingContextBuilder.build(finding, verdict=verdict)
    assert ctx.finding_id == "F-201"
    assert ctx.rule_id == "RULE-XSS"
    assert ctx.verdict_status == "VULNERABLE"
    assert ctx.variable_version == "$name#2"
    assert ctx.call_context == "ctx_req_1"
    assert ctx.branch_polarity == "TRUE"
    assert ctx.evidence_fingerprint != ""
    assert ctx.canonical_fingerprint != ""


def test_context_builder_unknown_verdict_preserves_not_available() -> None:
    finding = Finding(
        finding_id="F-202",
        rule_id="RULE-CUSTOM",
        fingerprint="fp_custom",
        title="Generic Finding",
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        cwe_id="CWE-20",
        owasp="A04:2021",
        file_path=Path("app/main.py"),
        evidence=Evidence(snippet="process_data(raw_input)", line=10, column=1),
        description="Potential validation issue.",
        remediation="Validate input.",
        verdict=None,
    )

    ctx = SecurityFindingContextBuilder.build(finding)
    assert ctx.verdict_status == "UNKNOWN"
    assert ctx.verdict_confidence == "UNKNOWN"
    assert ctx.variable_version == "$x#0"
    assert ctx.call_context == "GLOBAL"
    assert ctx.sanitizer_evidence == ()


def test_context_builder_cross_file_detection() -> None:
    ee = FindingEvidence(
        snippet="db.execute(sql)",
        line=30,
        column=1,
        source_symbol="src/controller.py:5",
        sink_symbol="src/db/query.py:30",
        sink_category="SQL_EXECUTION",
    )

    finding = QualifiedFinding(
        finding_id="F-203",
        rule_id="RULE-SQLI",
        fingerprint="fp_cross",
        title="Cross File SQLi",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        cwe_id="CWE-89",
        owasp="A03:2021",
        file_path=Path("src/db/query.py"),
        evidence=Evidence(snippet="db.execute(sql)", line=30, column=1),
        description="Cross file taint flow.",
        remediation="Parameterize",
        qualification_state=QualificationState.CONFIRMED,
        enriched_evidence=ee,
    )

    ctx = SecurityFindingContextBuilder.build(finding)
    assert ctx.sink_category == "SQL_EXECUTION"
