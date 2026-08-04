"""BasePredicate abstract class for ASTMatcher predicate plugins."""

from abc import ABC, abstractmethod
from typing import Optional, Tuple
from karsasec.parser.ast.context import VisitorContext
from karsasec.parser.ast_nodes import ASTNode
from karsasec.rules.matcher.compiler import CompiledRule
from karsasec.rules.matcher.statistics import MatcherStatistics

class BasePredicate(ABC):
    """Abstract base class for individual rule matching predicates."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Predicate identifier name."""
        pass

    @abstractmethod
    def evaluate(
        self,
        node: ASTNode,
        compiled_rule: CompiledRule,
        context: VisitorContext,
        stats: MatcherStatistics,
        source_bytes: bytes = b"",
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """Evaluates predicate against node and context.

        Returns:
            Tuple[bool, Optional[str], Optional[str]]: (matched, matched_symbol, matched_text)
        """
        pass
