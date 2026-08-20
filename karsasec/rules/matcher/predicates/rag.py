"""RAGPredicate plugin for rule predicates that need retrieval context.

This predicate enables rules to opt-in to RAG-based checks by adding
metadata tags such as `use_rag` or `rag_contains:<substring>` in the
rule metadata `tags` list. It inspects `context.rag_context` and
succeeds only when required RAG constraints are satisfied.
"""

from karsasec.parser.ast.context import VisitorContext
from karsasec.parser.ast_nodes import ASTNode
from karsasec.rules.matcher.compiler import CompiledRule
from karsasec.rules.matcher.predicates.base import BasePredicate
from karsasec.rules.matcher.statistics import MatcherStatistics


class RAGPredicate(BasePredicate):
    @property
    def name(self) -> str:
        return "RAGPredicate"

    def evaluate(
        self,
        node: ASTNode,
        compiled_rule: CompiledRule,
        context: VisitorContext,
        stats: MatcherStatistics,
        source_bytes: bytes = b"",
    ) -> tuple[bool, str | None, str | None]:
        # If rule has no RAG-related tags, this predicate is a no-op and passes.
        tags = getattr(compiled_rule.rule.metadata, "tags", []) or []

        # Simpler: consider tags that start with 'use_rag' or 'rag_contains:'
        if not tags or not any(t.startswith("use_rag") or t.startswith("rag_contains:") for t in tags):
            return True, None, None

        # If we require RAG but context is empty, fail
        rag_ctx = getattr(context, "rag_context", None) or ()
        if not rag_ctx:
            return False, None, None

        # Evaluate rag_contains tags if present
        for t in tags:
            if not t.startswith("rag_contains:"):
                continue
            wanted = t.split("rag_contains:", 1)[1]
            found = False
            for item in rag_ctx:
                text = item.get("text") or ""
                if wanted.lower() in text.lower():
                    found = True
                    break
            if not found:
                return False, None, None

        # All RAG constraints satisfied
        return True, None, None
