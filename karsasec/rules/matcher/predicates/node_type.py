"""NodeTypePredicate plugin evaluating language scope and AST node_type."""

from karsasec.parser.ast.context import VisitorContext
from karsasec.parser.ast_nodes import ASTNode
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
    ) -> tuple[bool, str | None, str | None]:
        stats.predicates_checked += 1
        rule = compiled_rule.rule

        # 1. Language Scope check
        if context.language:
            rule_lang = rule.match.language.value if hasattr(rule.match.language, "value") else str(rule.match.language)
            if (
                rule_lang.lower() != context.language.lower()
                and rule_lang.lower() != "generic"
                and context.language.lower() != "generic"
            ):
                stats.short_circuit += 1
                return False, None, None

        # 2. Node Type check
        if compiled_rule.ast_node_types_set and "*" not in compiled_rule.ast_node_types_set:
            node_type_clean = node.node_type.lower()
            if node_type_clean not in compiled_rule.ast_node_types_set:
                stats.short_circuit += 1
                return False, None, None

        return True, None, None
