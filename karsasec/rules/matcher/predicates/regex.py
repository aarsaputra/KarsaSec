"""RegexPredicate plugin evaluating pre-compiled regular expression patterns against node text."""

import re
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
        
        # Semantic expansion: If semantic graph is present, try to resolve variable text
        expanded_texts = [node_text]
        if getattr(context, "semantic_graph", None):
            scopes = getattr(context.semantic_graph, "scopes", {})
            file_node = getattr(context, "file_node", None)
            
            # Find the enclosing scope
            node_scope = None
            if file_node and scopes:
                curr_id = node.node_id
                while curr_id:
                    if curr_id in scopes:
                        node_scope = scopes[curr_id]
                        break
                    p_node = file_node.nodes_map.get(curr_id) if file_node.nodes_map else None
                    curr_id = p_node.parent_id if p_node else None
                if not node_scope and file_node.node_id in scopes:
                    node_scope = scopes[file_node.node_id]

            words = set(re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", node_text))
            for word in words:
                if word in ("if", "else", "for", "func", "return", "var", "const", "let", "import", "package"):
                    continue
                resolved = None
                if node_scope:
                    resolved = node_scope.lookup(word)
                if not resolved:
                    resolved = context.semantic_graph.alias_tracker.resolve(word)
                    if resolved == word:
                        resolved = None
                
                if resolved:
                    expanded = re.sub(r"\b" + re.escape(word) + r"\b", resolved, node_text)
                    expanded_texts.append(expanded)

        for text_to_check in expanded_texts:
            match = pattern.search(text_to_check)
            if match:
                return True, None, match.group(0)

        stats.short_circuit += 1
        return False, None, None
