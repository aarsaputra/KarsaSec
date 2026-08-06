"""Unit tests for Rule Schema v2 and Schema v1 backward compatibility."""

from karsasec.rules.enums import LanguageEnum, Severity
from karsasec.rules.schema import (
    AnalysisBehavior,
    AnalysisEngine,
    Rule,
    validate_rule_dict,
)


def test_schema_v1_backward_compatibility() -> None:
    raw_v1 = {
        "rule": {"id": "KS-PY-0001"},
        "metadata": {
            "name": "SQL Injection",
            "author": "KarsaSec",
            "version": "1.0",
            "cwe": "CWE-89",
            "owasp": "A03:2021-Injection",
        },
        "match": {
            "language": "Python",
            "ast_node_types": ["call"],
        },
        "condition": {
            "symbol_triggers": ["cursor.execute"],
        },
        "output": {
            "severity": "HIGH",
            "confidence": "CONFIDENT",
            "message": "SQLi detected",
            "remediation": "Use parameterized queries",
        },
    }

    rule = validate_rule_dict(raw_v1)
    assert isinstance(rule, Rule)
    assert rule.id == "KS-PY-0001"
    assert rule.match.language == LanguageEnum.PYTHON
    assert rule.output.severity == Severity.HIGH
    assert rule.schema_version == "1.0"

def test_schema_v2_full_features() -> None:
    raw_v2 = {
        "rule": {"id": "KS-PY-0002"},
        "metadata": {
            "name": "Command Injection",
            "author": "KarsaSec Team",
            "version": "2.0",
            "cwe": "CWE-78",
            "owasp": "A03:2021-Injection",
            "created": "2026-08-05",
            "references": ["https://cwe.mitre.org/data/definitions/78.html"],
            "tags": ["injection", "command"],
        },
        "target": {
            "languages": ["Python"],
            "frameworks": ["Django", "Flask"],
        },
        "analysis": {
            "engine": "AST",
            "behavior": "SINK",
        },
        "match": {
            "language": "Python",
            "ast_node_types": ["call"],
        },
        "condition": {
            "symbol_triggers": ["os.system", "subprocess.Popen"],
        },
        "evidence": {
            "require": ["user_input"],
            "score_weights": {"dangerous_sink": 40, "user_source": 30},
        },
        "output": {
            "severity": "CRITICAL",
            "confidence": "CONFIDENT",
            "message": "Command injection detected",
            "remediation": "Do not use shell=True",
        },
    }

    rule = validate_rule_dict(raw_v2)
    assert rule.schema_version == "2.0"
    assert rule.analysis.engine == AnalysisEngine.AST
    assert rule.analysis.behavior == AnalysisBehavior.SINK
    assert rule.evidence.score_weights["dangerous_sink"] == 40
    assert "Django" in rule.target.frameworks
    assert "injection" in rule.metadata.tags
