"""Comprehensive unit test suite for ASTMatcher, PredicatePipeline, and RuleMatch models."""

import pytest
from pathlib import Path

from karsasec.core.plugin import SymbolTable
from karsasec.parser.ast import VisitorContext
from karsasec.parser.ast_nodes import ASTNode, FileNode
from karsasec.rules.enums import LanguageEnum, Severity
from karsasec.rules.matcher import (
    ASTMatcher,
    CompiledRule,
    MatcherStatistics,
    RuleIncompatibleError,
    RuleMatch,
    check_rule_compatibility,
    rule_compiler,
)
from karsasec.rules.schema import Rule, RuleCondition, RuleMatch as RuleMatchSchema, RuleMetadata, RuleOutput

def create_dummy_rule(
    rule_id: str = "KS-PY-0001",
    language: LanguageEnum = LanguageEnum.PYTHON,
    node_types: list = None,
    symbol_triggers: list = None,
    pattern: str = None,
    version: str = "1.0",
) -> Rule:
    return Rule(
        id=rule_id,
        metadata=RuleMetadata(name="Test Rule", author="KarsaSec", version=version, enabled=True),
        match=RuleMatchSchema(language=language, ast_node_types=node_types or ["call_expression"]),
        condition=RuleCondition(symbol_triggers=symbol_triggers or [], pattern=pattern),
        output=RuleOutput(severity=Severity.HIGH, confidence="CONFIDENT", message="Test match", remediation="Fix"),
    )

def test_frozen_rule_match_immutability() -> None:
    match_res = RuleMatch(
        matched=True,
        rule_id="KS-PY-0001",
        node_id="node_123",
        matched_symbol="os.system",
        matched_text="os.system(cmd)",
        matched_predicates=("NodeTypePredicate", "SymbolPredicate"),
    )
    assert match_res.matched is True
    assert match_res.rule_id == "KS-PY-0001"
    with pytest.raises(AttributeError):
        match_res.matched = False  # Frozen dataclass check

def test_language_mismatch_short_circuit() -> None:
    rule = create_dummy_rule(language=LanguageEnum.PYTHON)
    node = ASTNode(node_id="node_1", node_type="call_expression")
    context = VisitorContext(file_node=FileNode(node_id="f1", node_type="file", language="javascript"), language="javascript")

    matcher = ASTMatcher()
    result = matcher.match(node, rule, context)

    assert result.matched is False
    assert matcher.statistics.short_circuit > 0

def test_node_mismatch_short_circuit() -> None:
    rule = create_dummy_rule(node_types=["call_expression"])
    node = ASTNode(node_id="node_1", node_type="function_definition")
    context = VisitorContext(file_node=FileNode(node_id="f1", node_type="file", language="python"), language="python")

    matcher = ASTMatcher()
    result = matcher.match(node, rule, context)

    assert result.matched is False
    assert matcher.statistics.short_circuit > 0

def test_symbol_success() -> None:
    rule = create_dummy_rule(symbol_triggers=["os.system"])
    src = b"os.system('ls')"
    node = ASTNode(node_id="node_1", node_type="call_expression", byte_start=0, byte_end=len(src))
    context = VisitorContext(file_node=FileNode(node_id="f1", node_type="file", language="python"), language="python")

    matcher = ASTMatcher()
    result = matcher.match(node, rule, context, source_bytes=src)

    assert result.matched is True
    assert result.matched_symbol == "os.system"

def test_symbol_fail() -> None:
    rule = create_dummy_rule(symbol_triggers=["os.system"])
    src = b"print('hello')"
    node = ASTNode(node_id="node_1", node_type="call_expression", byte_start=0, byte_end=len(src))
    context = VisitorContext(file_node=FileNode(node_id="f1", node_type="file", language="python"), language="python")

    matcher = ASTMatcher()
    result = matcher.match(node, rule, context, source_bytes=src)

    assert result.matched is False

def test_regex_success() -> None:
    rule = create_dummy_rule(pattern=r"eval\(.*\)")
    src = b"eval(user_input)"
    node = ASTNode(node_id="node_1", node_type="call_expression", byte_start=0, byte_end=len(src))
    context = VisitorContext(file_node=FileNode(node_id="f1", node_type="file", language="python"), language="python")

    matcher = ASTMatcher()
    result = matcher.match(node, rule, context, source_bytes=src)

    assert result.matched is True
    assert result.matched_text == "eval(user_input)"

def test_regex_fail() -> None:
    rule = create_dummy_rule(pattern=r"eval\(.*\)")
    src = b"safe_func()"
    node = ASTNode(node_id="node_1", node_type="call_expression", byte_start=0, byte_end=len(src))
    context = VisitorContext(file_node=FileNode(node_id="f1", node_type="file", language="python"), language="python")

    matcher = ASTMatcher()
    result = matcher.match(node, rule, context, source_bytes=src)

    assert result.matched is False

def test_compiled_regex_optimization() -> None:
    rule = create_dummy_rule(pattern=r"exec\(.*\)")
    compiled = rule_compiler.compile(rule)

    assert isinstance(compiled, CompiledRule)
    assert compiled.compiled_pattern is not None

    src = b"exec(cmd)"
    node = ASTNode(node_id="node_1", node_type="call_expression", byte_start=0, byte_end=len(src))
    context = VisitorContext(file_node=FileNode(node_id="f1", node_type="file", language="python"), language="python")

    matcher = ASTMatcher()
    result = matcher.match(node, compiled, context, source_bytes=src)
    assert result.matched is True

def test_matcher_statistics_counters() -> None:
    rule = create_dummy_rule(symbol_triggers=["exec"])
    src = b"exec(code)"
    node = ASTNode(node_id="node_1", node_type="call_expression", byte_start=0, byte_end=len(src))
    context = VisitorContext(file_node=FileNode(node_id="f1", node_type="file", language="python"), language="python")

    matcher = ASTMatcher()
    matcher.match(node, rule, context, source_bytes=src)

    stats_dict = matcher.statistics.to_dict()
    assert stats_dict["nodes_checked"] == 1
    assert stats_dict["rules_checked"] == 1
    assert stats_dict["predicates_checked"] > 0

def test_compatibility_valid_and_invalid() -> None:
    valid_rule = create_dummy_rule(version="1.0")
    check_rule_compatibility(valid_rule)  # Should not raise exception

    invalid_rule = create_dummy_rule(version="99.0")
    with pytest.raises(RuleIncompatibleError):
        check_rule_compatibility(invalid_rule)

def test_empty_predicate_handling() -> None:
    rule = create_dummy_rule()  # No symbols, no pattern
    node = ASTNode(node_id="node_1", node_type="call_expression")
    context = VisitorContext(file_node=FileNode(node_id="f1", node_type="file", language="python"), language="python")

    matcher = ASTMatcher()
    result = matcher.match(node, rule, context)

    assert result.matched is True  # Matches because node_type and language match

def test_invalid_regex_pattern_compilation() -> None:
    rule = create_dummy_rule(pattern=r"[invalid regex")
    with pytest.raises(ValueError, match="Invalid regex pattern"):
        rule_compiler.compile(rule)

def test_symbol_table_import_lookup() -> None:
    rule = create_dummy_rule(symbol_triggers=["subprocess"])
    node = ASTNode(node_id="node_1", node_type="call_expression")

    sym_table = SymbolTable(imports=["subprocess"])

    context = VisitorContext(
        file_node=FileNode(node_id="f1", node_type="file", language="python"),
        symbol_table=sym_table,
        language="python",
    )

    matcher = ASTMatcher()
    result = matcher.match(node, rule, context)

    assert result.matched is True
    assert result.matched_symbol == "subprocess"
