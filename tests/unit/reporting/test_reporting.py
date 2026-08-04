"""Unit tests for FindingCollection, JSONReporter, SARIFReporter, ConsoleReporter, and ReportTargets."""

import json
import pytest
from pathlib import Path

from karsasec.core.execution.result import ExecutionResult
from karsasec.core.finding import Evidence, Finding, FindingCollection
from karsasec.core.reporting import (
    ConsoleReporter,
    FileTarget,
    JSONReporter,
    SARIFReporter,
    StringTarget,
)
from karsasec.rules.enums import Confidence, Severity

def create_mock_finding(
    rule_id: str = "KS-PY-001",
    severity: Severity = Severity.HIGH,
    snippet: str = "eval(input)",
) -> Finding:
    return Finding(
        finding_id="f1",
        rule_id=rule_id,
        fingerprint="fp1234567890",
        title="Insecure Eval Usage",
        severity=severity,
        confidence=Confidence.HIGH,
        cwe_id="CWE-95",
        owasp="A03:2021-Injection",
        file_path=Path("app.py"),
        evidence=Evidence(snippet=snippet, line=10, column=5, context_lines=("eval(input)",)),
        description="Eval call detected",
        remediation="Remove eval",
    )

def test_finding_collection_methods() -> None:
    f1 = create_mock_finding("R1", Severity.HIGH)
    f2 = create_mock_finding("R2", Severity.CRITICAL)
    f3 = create_mock_finding("R1", Severity.LOW)

    collection = FindingCollection((f1, f2, f3))

    assert collection.total == 3
    assert len(collection.by_severity(Severity.HIGH)) == 1

    sorted_col = collection.sort_by_severity(descending=True)
    assert sorted_col.findings[0].severity == Severity.CRITICAL

    filtered_col = collection.filter_by_min_severity(Severity.HIGH)
    assert filtered_col.total == 2

    grouped = collection.group_by_rule()
    assert len(grouped["R1"]) == 2

def test_json_reporter_output() -> None:
    f1 = create_mock_finding()
    res = ExecutionResult(
        scan_id="s1",
        timestamp="2026-08-05T00:00:00Z",
        files_scanned=1,
        rules_checked=10,
        nodes_processed=50,
        findings=(f1,),
        execution_time_ms=12.5,
    )

    target = StringTarget()
    reporter = JSONReporter()
    reporter.generate(res, target)

    data = json.loads(target.get_content())
    assert data["metadata"]["schema_version"] == "1.0"
    assert data["summary"]["total_findings"] == 1
    assert data["findings"][0]["rule_id"] == "KS-PY-001"

def test_sarif_reporter_output() -> None:
    f1 = create_mock_finding("R1", Severity.CRITICAL)
    f2 = create_mock_finding("R1", Severity.CRITICAL)  # Duplicate rule definition

    res = ExecutionResult(
        scan_id="s1",
        timestamp="2026-08-05T00:00:00Z",
        files_scanned=1,
        rules_checked=10,
        nodes_processed=50,
        findings=(f1, f2),
        execution_time_ms=12.5,
    )

    target = StringTarget()
    reporter = SARIFReporter()
    reporter.generate(res, target)

    data = json.loads(target.get_content())
    assert data["version"] == "2.1.0"
    assert len(data["runs"][0]["tool"]["driver"]["rules"]) == 1  # Deduplicated rules array
    assert len(data["runs"][0]["results"]) == 2

def test_console_reporter_output() -> None:
    f1 = create_mock_finding()
    res = ExecutionResult(
        scan_id="s1",
        timestamp="2026-08-05T00:00:00Z",
        files_scanned=1,
        rules_checked=10,
        nodes_processed=50,
        findings=(f1,),
        execution_time_ms=12.5,
    )

    target = StringTarget()
    reporter = ConsoleReporter(no_color=True)
    reporter.generate(res, target)

    content = target.get_content()
    assert "KARSASEC SECURITY SCAN REPORT" in content
    assert "[HIGH] Insecure Eval Usage" in content
