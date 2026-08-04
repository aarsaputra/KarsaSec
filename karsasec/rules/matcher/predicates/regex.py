"""RegexPredicate plugin evaluating pre-compiled regular expression patterns against node text."""

from typing import Optional, Tuple
from karsasec.parser.ast.context import VisitorContext
from karsasec.parser.ast_nodes import ASTNode
from karsasec.rules.matcher.compiler import CompiledRule
from karsasec.rules.matcher.predicates.base import BasePredicate
from karsasec.rules.matcher.statistics import MatcherStatistics

class RegexPredicate(BasePredicate):
    """Evaluates pre-compiled regular expression patterns against AST node text."""

    @property
    def name(self) -> str:
        return "RegexPredicate"

    def evaluate(
        self,
        node: ASTNode,
        compiled_rule: CompiledRule,
        context: VisitorContext,
        stats: MatcherStatistics,
        source_bytes: bytes = b"",
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        pattern = compiled_rule.compiled_pattern
        if not pattern:
            return True, None, None

        stats.predicates_checked += 1
        stats.regex_calls += 1

        node_text = node.get_text(source_bytes)
        match = pattern.search(node_text)

        if match:
            return True, None, match.group(0)

        stats.short_circuit += 1
        return False, None, None
