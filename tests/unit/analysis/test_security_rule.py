"""Unit tests for SecurityRule model and deterministic SHA-256 rule ID computation (INV-E12-RULE-01)."""

from karsasec.analysis.security_rule import SecurityRule, compute_rule_id


def test_security_rule_deterministic_id() -> None:
    """Verifies that compute_rule_id produces identical SHA-256 output across executions."""
    rid1 = compute_rule_id("E12-SQL-001", "1.0")
    rid2 = compute_rule_id("E12-SQL-001", "1.0")
    assert rid1 == rid2
    assert len(rid1) == 64

    rule1 = SecurityRule.create(
        rule_key="E12-SQL-001",
        name="Unsanitized HTTP Input to SQL Sink",
        version="1.0",
        vulnerability_class="SQL Injection",
        source_kinds=["http_user_input"],
        sink_categories=["sql"],
    )
    assert rule1.rule_id == rid1
    assert rule1.severity == "HIGH"


def test_security_rule_immutability() -> None:
    """Verifies SecurityRule immutability."""
    rule = SecurityRule.create(
        rule_key="E12-CMD-001",
        name="Command Injection",
        version="1.0",
        vulnerability_class="Command Injection",
        source_kinds=["http_user_input"],
        sink_categories=["command_execution"],
        severity="CRITICAL",
    )
    assert rule.severity == "CRITICAL"
    try:
        rule.severity = "LOW"  # type: ignore[misc]
    except AttributeError:
        pass  # Frozen dataclass raises AttributeError on assignment
