"""Qualification unit tests for ArtifactValidator framework."""

from pathlib import Path

from karsasec.core.finding.evidence import Evidence
from karsasec.core.finding.model import Finding
from karsasec.parser.ast_nodes import FileNode, Position
from karsasec.rules.enums import Confidence, Severity
from karsasec.runtime.artifact_validator import artifact_validator


def test_ast_validation_success():
    path = Path("test.py")
    node = FileNode("file1", "file", "Python", path, 0, 10, Position(1, 0), Position(5, 0), [], 5)
    report = artifact_validator.validate_ast(node)
    assert report.is_valid is True
    assert report.artifact_type == "AST"


def test_cfg_validation_success():
    cfg_data = {
        "entry_nodes": ["block_1"],
        "blocks": {"block_1": {}, "block_2": {}},
        "edges": [{"from": "block_1", "to": "block_2"}]
    }
    report = artifact_validator.validate_cfg(cfg_data)
    assert report.is_valid is True


def test_cfg_validation_failure_multiple_entries():
    cfg_data = {
        "entry_nodes": ["block_1", "block_2"],
        "blocks": {"block_1": {}, "block_2": {}},
        "edges": []
    }
    report = artifact_validator.validate_cfg(cfg_data)
    assert report.is_valid is False
    assert "exactly one entry node" in report.errors[0]


def test_finding_validation_success():
    evidence = Evidence(snippet="shell_exec($cmd)", line=10, column=0)
    finding = Finding(
        finding_id="f1",
        rule_id="KS-PHP-0001",
        fingerprint="sha256-hash-sample",
        title="RCE",
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIDENT,
        cwe_id="CWE-78",
        owasp="A03:2021-Injection",
        file_path=Path("index.php"),
        evidence=evidence,
        description="RCE detected",
        remediation="Avoid shell_exec",
    )
    report = artifact_validator.validate_findings([finding])
    assert report.is_valid is True
