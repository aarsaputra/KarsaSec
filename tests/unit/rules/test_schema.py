"""Unit tests for Rule Schema, Enums, and Finding DTO validation."""

import pytest
from pathlib import Path
from karsasec.rules.enums import Confidence, LanguageEnum, OWASPCategory, Severity
from karsasec.rules.finding import Finding
from karsasec.rules.schema import validate_rule_dict

def test_valid_rule_schema() -> None:
    raw = {
        "rule": {"id": "KS-PY-0001"},
        "metadata": {
            "name": "SQL Injection",
            "author": "KarsaSec",
            "version": "1.0",
            "enabled": True,
            "cwe": "CWE-89",
            "owasp": "A03:2021-Injection",
        },
        "match": {
            "language": "Python",
            "ast_node_types": ["call"],
        },
        "condition": {
            "symbol_triggers": ["execute"],
        },
        "output": {
            "severity": "HIGH",
            "confidence": "CONFIDENT",
            "message": "SQLi detected.",
            "remediation": "Use parameterized queries.",
        },
    }

    rule = validate_rule_dict(raw)
    assert rule.id == "KS-PY-0001"
    assert rule.metadata.name == "SQL Injection"
    assert rule.match.language == LanguageEnum.PYTHON
    assert rule.output.severity == Severity.HIGH
    assert rule.output.confidence == Confidence.CONFIDENT

def test_invalid_rule_id_format() -> None:
    raw = {
        "rule": {"id": "invalid_id_format"},
        "match": {"language": "Python"},
        "output": {"severity": "HIGH"},
    }
    with pytest.raises(ValueError, match="Invalid Rule ID format"):
        validate_rule_dict(raw)

def test_invalid_language_enum() -> None:
    raw = {
        "rule": {"id": "KS-PY-0001"},
        "match": {"language": "Brainfuck"},
        "output": {"severity": "HIGH"},
    }
    with pytest.raises(ValueError, match="Invalid language"):
        validate_rule_dict(raw)

def test_invalid_severity_enum() -> None:
    raw = {
        "rule": {"id": "KS-PY-0001"},
        "match": {"language": "Python"},
        "output": {"severity": "ULTRA_HIGH"},
    }
    with pytest.raises(ValueError, match="Invalid severity"):
        validate_rule_dict(raw)

def test_immutable_finding() -> None:
    finding = Finding(
        id="find-123",
        rule_id="KS-PY-0001",
        title="SQL Injection",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIDENT,
        cwe_id="CWE-89",
        owasp=OWASPCategory.A03_2025_INJECTION.value,
        file_path=Path("app.py"),
        line=10,
        column=4,
        node_id="abc1234567890def",
        rule_version="1.0",
        parser_version="0.1.0",
        evidence="cursor.execute(query)",
        description="SQLi detected",
        remediation="Parametrize query",
    )
    assert finding.rule_id == "KS-PY-0001"
    with pytest.raises(AttributeError):
        finding.severity = Severity.LOW  # Should fail because dataclass is frozen
