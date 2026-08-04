"""AST Matcher subpackage for evaluating security rules against AST nodes."""

from karsasec.rules.matcher.compatibility import CURRENT_MATCHER_VERSION, RuleIncompatibleError, check_rule_compatibility
from karsasec.rules.matcher.compiler import CompiledRule, RuleCompiler, rule_compiler
from karsasec.rules.matcher.context import MatcherContext
from karsasec.rules.matcher.matcher import ASTMatcher, ast_matcher
from karsasec.rules.matcher.predicates import (
    BasePredicate,
    LiteralPredicate,
    NodeTypePredicate,
    PredicatePipeline,
    RegexPredicate,
    SymbolPredicate,
)
from karsasec.rules.matcher.result import RuleMatch
from karsasec.rules.matcher.statistics import MatcherStatistics

__all__ = [
    "RuleMatch",
    "MatcherContext",
    "MatcherStatistics",
    "CompiledRule",
    "RuleCompiler",
    "rule_compiler",
    "ASTMatcher",
    "ast_matcher",
    "RuleIncompatibleError",
    "check_rule_compatibility",
    "CURRENT_MATCHER_VERSION",
    "BasePredicate",
    "NodeTypePredicate",
    "SymbolPredicate",
    "RegexPredicate",
    "LiteralPredicate",
    "PredicatePipeline",
]
