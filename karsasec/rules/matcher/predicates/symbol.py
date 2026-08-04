"""SymbolPredicate plugin evaluating symbol triggers against AST node text and SymbolTable metadata."""

import re
from typing import Optional, Tuple
from karsasec.parser.ast.context import VisitorContext
from karsasec.parser.ast_nodes import ASTNode
from karsasec.rules.matcher.compiler import CompiledRule
from karsasec.rules.matcher.predicates.base import BasePredicate
from karsasec.rules.matcher.statistics import MatcherStatistics

class SymbolPredicate(BasePredicate):
    """Evaluates symbol triggers against AST node identifiers and SymbolTable metadata."""

    @property
    def name(self) -> str:
        return "SymbolPredicate"

    def evaluate(
        self,
        node: ASTNode,
        compiled_rule: CompiledRule,
        context: VisitorContext,
        stats: MatcherStatistics,
        source_bytes: bytes = b"",
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        triggers = compiled_rule.cleaned_symbol_triggers
        if not triggers:
            return True, None, None

        stats.predicates_checked += 1
        node_text = node.get_text(source_bytes)

        # 1. Exact or word-boundary text search for symbol trigger in node_text
        for trigger in triggers:
            # If trigger contains dots (e.g. cursor.execute or exec.Command) or special chars, escape it
            pattern = r"(?:\b|_)" + re.escape(trigger) + r"(?:\b|_)" if "." not in trigger else re.escape(trigger)
            if re.search(pattern, node_text):
                return True, trigger, node_text

        # 2. SymbolTable metadata search
        if context.symbol_table:
            # Check function definitions or calls in symbol table
            if hasattr(context.symbol_table, "functions") and context.symbol_table.functions:
                for fn in context.symbol_table.functions:
                    fn_name = getattr(fn, "name", str(fn))
                    for trigger in triggers:
                        if trigger == fn_name or trigger in fn_name:
                            return True, trigger, fn_name

            # Check imports in symbol table
            if hasattr(context.symbol_table, "imports") and context.symbol_table.imports:
                for imp in context.symbol_table.imports:
                    imp_name = getattr(imp, "module_name", getattr(imp, "name", str(imp)))
                    for trigger in triggers:
                        if trigger == imp_name or trigger in imp_name:
                            return True, trigger, imp_name

        stats.short_circuit += 1
        return False, None, None
