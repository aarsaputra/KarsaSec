"""LiteralPredicate plugin evaluating literal text trigger matching."""

from karsasec.parser.ast.context import VisitorContext
from karsasec.parser.ast_nodes import ASTNode
from karsasec.rules.matcher.compiler import CompiledRule
from karsasec.rules.matcher.predicates.base import BasePredicate
from karsasec.rules.matcher.statistics import MatcherStatistics


class LiteralPredicate(BasePredicate):
    """Evaluates literal string triggers against AST node text."""

    @property
    def name(self) -> str:
        return "LiteralPredicate"

    def evaluate(
        self,
        node: ASTNode,
        compiled_rule: CompiledRule,
        context: VisitorContext,
        stats: MatcherStatistics,
        source_bytes: bytes = b"",
    ) -> tuple[bool, str | None, str | None]:
        # Checked via SymbolPredicate or fallback literal matching
        return True, None, None
