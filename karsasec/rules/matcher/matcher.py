"""ASTMatcher main entry point for evaluating rules against AST nodes."""

import time

from karsasec.parser.ast.context import VisitorContext
from karsasec.parser.ast_nodes import ASTNode
from karsasec.rules.matcher.compatibility import check_rule_compatibility
from karsasec.rules.matcher.compiler import CompiledRule, rule_compiler
from karsasec.rules.matcher.predicates.pipeline import PredicatePipeline
from karsasec.rules.matcher.result import RuleMatch
from karsasec.rules.matcher.statistics import MatcherStatistics
from karsasec.rules.schema import Rule


class ASTMatcher:
    """Deterministic AST Rule Matcher evaluating node predicates and returning RuleMatch DTOs."""

    def __init__(
        self,
        pipeline: PredicatePipeline | None = None,
        statistics: MatcherStatistics | None = None,
    ) -> None:
        self.pipeline = pipeline or PredicatePipeline()
        self.statistics = statistics or MatcherStatistics()

    def match(
        self,
        node: ASTNode,
        rule: Rule | CompiledRule,
        context: VisitorContext,
        source_bytes: bytes = b"",
    ) -> RuleMatch:
        """Evaluates whether an ASTNode satisfies a target Rule.

        Args:
            node: Target ASTNode instance.
            rule: Raw Rule or CompiledRule definition.
            context: VisitorContext containing language, symbol table, and file metadata.
            source_bytes: Optional raw source code bytes.

        Returns:
            RuleMatch: Immutable result dataclass carrying match decision and debug metadata.
        """
        start_ns = time.perf_counter_ns()
        self.statistics.nodes_checked += 1
        self.statistics.rules_checked += 1

        # 1. Ensure rule compilation
        compiled_rule: CompiledRule
        if isinstance(rule, CompiledRule):
            compiled_rule = rule
        else:
            compiled_rule = rule_compiler.compile(rule)

        # 2. Check rule compatibility
        check_rule_compatibility(compiled_rule.rule)

        # 3. Evaluate Predicate Pipeline
        is_match, symbol, text, matched_preds, failure_reason = self.pipeline.evaluate_all(
            node=node,
            compiled_rule=compiled_rule,
            context=context,
            stats=self.statistics,
            source_bytes=source_bytes,
        )

        eval_time_ns = time.perf_counter_ns() - start_ns
        self.statistics.total_time_ns += eval_time_ns

        return RuleMatch(
            matched=is_match,
            rule_id=compiled_rule.id,
            node_id=node.node_id,
            matched_symbol=symbol,
            matched_text=text,
            matched_predicates=matched_preds,
            failure_reason=failure_reason,
            evaluation_time_ns=eval_time_ns,
        )

# Global default ASTMatcher instance
ast_matcher = ASTMatcher()
