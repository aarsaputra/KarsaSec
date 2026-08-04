"""NodeTypePredicate plugin evaluating language scope and AST node_type."""

from typing import Optional, Tuple
from karsasec.parser.ast.context import VisitorContext
from karsasec.parser.ast_nodes import ASTNode
from karsasec.rules.enums import LanguageEnum
from karsasec.rules.matcher.compiler import CompiledRule
from karsasec.rules.matcher.predicates.base import BasePredicate
from karsasec.rules.matcher.statistics import MatcherStatistics

class NodeTypePredicate(BasePredicate):
    """Evaluates language scope and AST node_type matching with instant short-circuiting."""

    @property
    def name(self) -> str:
        return "NodeTypePredicate"

    def evaluate(
        self,
        node: ASTNode,
        compiled_rule: CompiledRule,
        context: VisitorContext,
        stats: MatcherStatistics,
        source_bytes: bytes = b"",
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        stats.predicates_checked += 1
        rule = compiled_rule.rule

        # 1. Language Scope check
        if context.language:
            rule_lang = rule.match.language.value if isinstance(rule.match.language, LanguageEnum) else str(rule.match.language)
            if rule_lang.lower() != context.language.lower():
                stats.short_circuit += 1
                return False, None, None

        # 2. Node Type check
        if compiled_rule.ast_node_types_set and "*" not in compiled_rule.ast_node_types_set:
            node_type_clean = node.node_type.lower()
            if node_type_clean not in compiled_rule.ast_node_types_set:
                stats.short_circuit += 1
                return False, None, None

        return True, None, None
