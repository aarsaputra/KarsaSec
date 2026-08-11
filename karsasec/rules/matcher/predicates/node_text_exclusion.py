"""NodeTextExclusionPredicate: short-circuits matching when node text matches an exclusion regex.

Prevents false positives from:
- PHP PDO ->fetch() being flagged as SSRF (KS-OWASP-0010)
- JS console.error/log string content containing 'fetch' being flagged as SSRF
- HTML documentation prose containing 'cookie'/'session'/'token' triggering A01
"""

import re

from karsasec.parser.ast.context import VisitorContext
from karsasec.parser.ast_nodes import ASTNode
from karsasec.rules.matcher.compiler import CompiledRule
from karsasec.rules.matcher.predicates.base import BasePredicate
from karsasec.rules.matcher.statistics import MatcherStatistics

_COMPILED_CACHE: dict[str, re.Pattern[str]] = {}


def _get_compiled(pattern: str) -> re.Pattern[str]:
    if pattern not in _COMPILED_CACHE:
        _COMPILED_CACHE[pattern] = re.compile(pattern, re.IGNORECASE | re.DOTALL)
    return _COMPILED_CACHE[pattern]


class NodeTextExclusionPredicate(BasePredicate):
    """Short-circuits rule matching when the full node text matches a node_text_not_matches regex.

    If the node text matches the exclusion pattern, the predicate returns False (no match),
    preventing downstream predicates from firing and eliminating false positives caused by
    string literals, error messages, HTML prose, and method call name collisions.
    """

    @property
    def name(self) -> str:
        return "NodeTextExclusionPredicate"

    def evaluate(
        self,
        node: ASTNode,
        compiled_rule: CompiledRule,
        context: VisitorContext,
        stats: MatcherStatistics,
        source_bytes: bytes = b"",
    ) -> tuple[bool, str | None, str | None]:
        condition = getattr(compiled_rule.rule, "condition", None)
        if not condition:
            return True, None, None

        exclusion_pattern = getattr(condition, "node_text_not_matches", None)
        if not exclusion_pattern:
            return True, None, None

        stats.predicates_checked += 1
        node_text = node.get_text(source_bytes)
        if not node_text:
            return True, None, None

        compiled = _get_compiled(exclusion_pattern)
        if compiled.search(node_text):
            stats.short_circuit += 1
            return False, None, None

        return True, None, None
