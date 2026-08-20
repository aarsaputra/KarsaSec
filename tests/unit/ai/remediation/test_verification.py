"""Unit tests for PostApplyVerificationEngine and semantic contracts (Sprint E13-4)."""

from __future__ import annotations

from pathlib import Path

from karsasec.ai.remediation.verification import PostApplyVerificationEngine, VerificationContract, VerificationStatus
from karsasec.core.finding.evidence import Evidence
from karsasec.core.finding.model import Finding
from karsasec.graph.dataflow.security_verdict import DecisionReason, SecurityVerdict, VerdictConfidence, VerdictStatus
from karsasec.rules.enums import Confidence, Severity


def _create_mock_finding(
    finding_id: str = "F-301", rule_id: str = "CWE-89-SQLI", file_path: str = "app.py", cwe_id: str | None = None
) -> Finding:
    cwe = cwe_id or ("CWE-79" if "CWE-79" in rule_id else "CWE-89")
    v = SecurityVerdict.create(
        status=VerdictStatus.VULNERABLE,
        confidence=VerdictConfidence.HIGH,
        rule_id=rule_id,
        sink_id="sink_01",
        sink_category="SQL_EXECUTION" if "CWE-89" in rule_id else "XSS_OUTPUT",
        file_path=file_path,
        function_name="handle_req",
        line_number=10,
        variable_version="$sql#1",
        call_context="GLOBAL",
        branch_polarity="UNKNOWN",
        reason_codes=(DecisionReason.TAINT_REACHES_SINK,),
        provenance_path=("app.py:1", "app.py:10"),
    )
    ev = Evidence(snippet="cursor.execute(sql)", line=10, column=1)
    return Finding(
        finding_id=finding_id,
        rule_id=rule_id,
        fingerprint=f"fp_{finding_id}",
        title=f"Finding {rule_id}",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe_id=cwe,
        owasp="A03:2021",
        file_path=Path(file_path),
        evidence=ev,
        description="Vulnerability description.",
        remediation="Remediation guidance.",
        verdict=v,
    )


def test_01_verification_contract_creation() -> None:
    finding = _create_mock_finding()
    contract = VerificationContract.from_finding(finding)

    assert contract.finding_id == "F-301"
    assert contract.rule_id == "CWE-89-SQLI"
    assert contract.cwe_id == "CWE-89"
    assert contract.sink_category == "SQL_EXECUTION"
    assert contract.file_path == "app.py"


def test_02_verified_fixed_when_no_matching_findings() -> None:
    finding = _create_mock_finding()
    engine = PostApplyVerificationEngine()

    # Empty post-apply scan results (vulnerability eliminated)
    res = engine.verify(finding=finding, post_apply_findings=())

    assert res.status == VerificationStatus.VERIFIED_FIXED
    assert res.post_apply_verdict_status == "SAFE"
    assert res.matching_findings_count == 0
    assert "successfully eliminated" in res.details


def test_03_still_vulnerable_when_semantic_finding_persists() -> None:
    finding = _create_mock_finding("F-301")
    engine = PostApplyVerificationEngine()

    # Post-apply scan yields new finding with different finding_id but same rule/file/sink
    new_post_finding = _create_mock_finding("F-999_NEW_ID")
    res = engine.verify(finding=finding, post_apply_findings=(new_post_finding,))

    assert res.status == VerificationStatus.STILL_VULNERABLE
    assert res.post_apply_verdict_status == "VULNERABLE"
    assert res.matching_findings_count == 1
    assert "persists post-patch" in res.details


def test_04_original_verdict_remains_immutable_h10() -> None:
    finding = _create_mock_finding()
    original_status = finding.verdict.status

    engine = PostApplyVerificationEngine()
    res = engine.verify(finding=finding, post_apply_findings=())

    # Assert original finding verdict was NOT mutated
    assert finding.verdict.status == original_status
    assert finding.verdict.status == VerdictStatus.VULNERABLE
    assert res.status == VerificationStatus.VERIFIED_FIXED


def test_05_different_file_finding_not_matched() -> None:
    finding = _create_mock_finding("F-301", file_path="app.py")
    other_file_finding = _create_mock_finding("F-302", file_path="other.py")

    engine = PostApplyVerificationEngine()
    res = engine.verify(finding=finding, post_apply_findings=(other_file_finding,))

    assert res.status == VerificationStatus.VERIFIED_FIXED
    assert res.matching_findings_count == 0


def test_06_different_rule_finding_not_matched() -> None:
    finding = _create_mock_finding("F-301", rule_id="CWE-89-SQLI")
    xss_finding = _create_mock_finding("F-302", rule_id="CWE-79-XSS")

    engine = PostApplyVerificationEngine()
    res = engine.verify(finding=finding, post_apply_findings=(xss_finding,))

    assert res.status == VerificationStatus.VERIFIED_FIXED


def test_07_verification_result_to_dict() -> None:
    finding = _create_mock_finding()
    engine = PostApplyVerificationEngine()
    res = engine.verify(finding=finding, post_apply_findings=())

    d = res.to_dict()
    assert d["finding_id"] == "F-301"
    assert d["status"] == "VERIFIED_FIXED"
    assert d["pre_apply_verdict_status"] == "VULNERABLE"
