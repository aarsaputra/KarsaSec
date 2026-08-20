"""Scalability benchmark measuring ASTMatcher throughput across 1, 10, 100, and 1000 rules."""

import time

from karsasec.parser.ast import VisitorContext
from karsasec.parser.ast_nodes import ASTNode, FileNode
from karsasec.rules.enums import LanguageEnum
from karsasec.rules.matcher import ASTMatcher, rule_compiler
from karsasec.rules.schema import Rule, RuleCondition, RuleMetadata, RuleOutput, Severity
from karsasec.rules.schema import RuleMatch as RuleMatchSchema


def create_compiled_rule(index: int) -> Rule:
    r = Rule(
        id=f"KS-PY-{index:04d}",
        metadata=RuleMetadata(name=f"Rule {index}", author="KarsaSec", version="1.0", enabled=True),
        match=RuleMatchSchema(language=LanguageEnum.PYTHON, ast_node_types=["call_expression"]),
        condition=RuleCondition(symbol_triggers=[f"trigger_{index}"], pattern=r"trigger_\d+"),
        output=RuleOutput(severity=Severity.HIGH, confidence="CONFIDENT", message="Match", remediation="Fix"),
    )
    return rule_compiler.compile(r)


def test_benchmark_matcher_scalability() -> None:
    node = ASTNode(node_id="n1", node_type="call_expression")
    context = VisitorContext(file_node=FileNode(node_id="f1", node_type="file", language="python"), language="python")
    source_bytes = b"trigger_50(param)"

    matcher = ASTMatcher()

    for rule_count in [1, 10, 100, 1000]:
        rules = [create_compiled_rule(i) for i in range(rule_count)]

        start_time = time.perf_counter()
        matches_found = 0

        for r in rules:
            res = matcher.match(node, r, context, source_bytes=source_bytes)
            if res.matched:
                matches_found += 1

        elapsed = time.perf_counter() - start_time
        eval_rate = rule_count / elapsed if elapsed > 0 else 0

        print(
            f"\n[Matcher Benchmark] {rule_count:4d} rules: {elapsed:.6f}s ({eval_rate:,.0f} matches/sec), matches={matches_found}"
        )
        assert elapsed >= 0
