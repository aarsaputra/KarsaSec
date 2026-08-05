"""PredicatePipeline orchestrating sequential short-circuiting predicate evaluation."""

from typing import List, Optional, Tuple
from karsasec.parser.ast.context import VisitorContext
from karsasec.parser.ast_nodes import ASTNode
from karsasec.rules.matcher.compiler import CompiledRule
from karsasec.rules.matcher.predicates.base import BasePredicate
from karsasec.rules.matcher.predicates.literal import LiteralPredicate
from karsasec.rules.matcher.predicates.node_type import NodeTypePredicate
from karsasec.rules.matcher.predicates.regex import RegexPredicate
from karsasec.rules.matcher.predicates.symbol import SymbolPredicate
from karsasec.rules.matcher.predicates.rag import RAGPredicate
from karsasec.rules.matcher.statistics import MatcherStatistics

class PredicatePipeline:
    """Orchestrates short-circuiting predicate evaluation across modular predicate plugins."""

    def __init__(self, predicates: Optional[List[BasePredicate]] = None) -> None:
        self.predicates: List[BasePredicate] = predicates or [
            NodeTypePredicate(),
            SymbolPredicate(),
            RAGPredicate(),
            RegexPredicate(),
            LiteralPredicate(),
        ]

    def evaluate_all(
        self,
        node: ASTNode,
        compiled_rule: CompiledRule,
        context: VisitorContext,
        stats: MatcherStatistics,
        source_bytes: bytes = b"",
    ) -> Tuple[bool, Optional[str], Optional[str], Tuple[str, ...], Optional[str]]:
        """Evaluates all predicates in sequence. Short-circuits immediately on failure.

        Returns:
            Tuple: (is_match, matched_symbol, matched_text, matched_predicates_tuple, failure_reason)
        """
        matched_predicates: List[str] = []
        matched_symbol: Optional[str] = None
        matched_text: Optional[str] = None

        for pred in self.predicates:
            is_match, symbol, text = pred.evaluate(node, compiled_rule, context, stats, source_bytes=source_bytes)

            if not is_match:
                return False, None, None, tuple(matched_predicates), f"Failed at predicate '{pred.name}'"

            matched_predicates.append(pred.name)
            if symbol and not matched_symbol:
                matched_symbol = symbol
            if text and not matched_text:
                matched_text = text

        return True, matched_symbol, matched_text, tuple(matched_predicates), None
