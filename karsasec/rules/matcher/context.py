"""MatcherContext model encapsulating node, rule, context, and source bytes."""

from dataclasses import dataclass

from karsasec.parser.ast.context import VisitorContext
from karsasec.parser.ast_nodes import ASTNode
from karsasec.rules.matcher.compiler import CompiledRule
from karsasec.rules.schema import Rule


@dataclass(slots=True)
class MatcherContext:
    """Encapsulates target ASTNode, Rule/CompiledRule, VisitorContext, and source code bytes."""

    node: ASTNode
    rule: Rule | CompiledRule
    context: VisitorContext
    source_bytes: bytes = b""
