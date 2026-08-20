"""Unit tests for RuleRegistry."""

import pytest

from karsasec.rules.enums import LanguageEnum, Severity
from karsasec.rules.registry import RuleRegistry
from karsasec.rules.schema import Rule, RuleCondition, RuleMatch, RuleMetadata, RuleOutput


def create_sample_rule(
    rule_id: str, language: LanguageEnum = LanguageEnum.PYTHON, node_types: list = None, enabled: bool = True
) -> Rule:
    return Rule(
        id=rule_id,
        metadata=RuleMetadata(name="Test Rule", author="KarsaSec", version="1.0", enabled=enabled),
        match=RuleMatch(language=language, ast_node_types=node_types or ["call"]),
        condition=RuleCondition(symbol_triggers=["eval"]),
        output=RuleOutput(severity=Severity.HIGH, confidence="CONFIDENT", message="Test", remediation="Fix"),
    )


def test_registry_registration_and_lookup() -> None:
    registry = RuleRegistry()
    rule1 = create_sample_rule("KS-PY-0001", node_types=["call"])
    rule2 = create_sample_rule("KS-PY-0002", node_types=["assignment"])

    registry.register(rule1)
    registry.register(rule2)

    assert registry.get_rule_by_id("KS-PY-0001") is rule1
    assert registry.get_rule_by_id("KS-PY-0002") is rule2

    call_rules = registry.get_rules_for_node(LanguageEnum.PYTHON, "call")
    assert len(call_rules) == 1
    assert call_rules[0].id == "KS-PY-0001"


def test_registry_duplicate_rule_id_prevention() -> None:
    registry = RuleRegistry()
    rule1 = create_sample_rule("KS-PY-0001")
    rule2 = create_sample_rule("KS-PY-0001")

    registry.register(rule1)
    with pytest.raises(ValueError, match="Duplicate Rule ID"):
        registry.register(rule2)


def test_registry_disabled_rule_filtering() -> None:
    registry = RuleRegistry()
    disabled_rule = create_sample_rule("KS-PY-0001", enabled=False)

    registry.register(disabled_rule)
    assert registry.get_rule_by_id("KS-PY-0001") is None
    assert len(registry.list_rules()) == 0
