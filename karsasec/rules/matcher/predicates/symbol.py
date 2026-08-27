"""SymbolPredicate plugin evaluating symbol triggers against AST node text and SymbolTable metadata.

# Resolution order (highest to lowest confidence):
# 0. Cross-file CallGraph resolution — checks if the node's call site is a known callee
#    in the project-wide CallGraph, resolving to the qualified symbol (e.g. 'module.Class.method')
# 1. Per-file SemanticGraph resolution — resolves aliases, imports, scopes for the current file
# 2. AST node text word-boundary search — direct text match for quick pattern detection
# 3. SymbolTable metadata search — function definitions and import declarations
"""

import re

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
    ) -> tuple[bool, str | None, str | None]:
        triggers = compiled_rule.cleaned_symbol_triggers
        if not triggers:
            return True, None, None

        stats.predicates_checked += 1
        node_text = node.get_text(source_bytes)

        # Step 0: Cross-file CallGraph resolution
        # Query if this call site is a known edge in the project-wide CallGraph
        call_graph = getattr(context, "call_graph", None)
        if call_graph is not None:
            edge = getattr(call_graph, "call_site_to_edge", {}).get(node.node_id)
            if edge is not None:
                resolved_qname = getattr(edge, "resolved_symbol", None)
                callee_id = getattr(edge, "callee_id", None)
                # Also try to get the full qualified name from the callee node
                callee_node = call_graph.get_node(callee_id) if callee_id and callee_id != "external" else None
                callee_qname = getattr(callee_node, "qualified_name", None) if callee_node else None

                for trigger in triggers:
                    # Match against resolved symbol string
                    if resolved_qname:
                        if (
                            trigger == resolved_qname
                            or resolved_qname.endswith("." + trigger)
                            or resolved_qname.startswith(trigger + ".")
                        ):
                            return True, trigger, resolved_qname
                    # Match against callee qualified name (cross-file)
                    if callee_qname:
                        if (
                            trigger == callee_qname
                            or callee_qname.endswith("." + trigger)
                            or callee_qname.startswith(trigger + ".")
                            or trigger.endswith("." + callee_qname.split(".")[-1])
                        ):
                            return True, trigger, callee_qname

        # Step 1: Per-file SemanticGraph resolution
        if getattr(context, "semantic_graph", None):
            try:
                resolved_symbol = context.semantic_graph.resolve_node(node.node_id)
            except RecursionError:
                # Protect against pathological semantic graphs causing recursion
                resolved_symbol = None

            if resolved_symbol:
                for trigger in triggers:
                    if (
                        trigger == resolved_symbol
                        or resolved_symbol.endswith("." + trigger)
                        or resolved_symbol.startswith(trigger + ".")
                        or trigger.endswith("." + resolved_symbol)
                    ):
                        return True, trigger, resolved_symbol

        # Special PHP Shorthand Echo support (<?= ... ?>)
        if context.language.lower() == "php" and "echo" in triggers:
            if node.parent_id and context.file_node:
                parent = context.file_node.nodes_map.get(node.parent_id)
                if parent:
                    try:
                        idx = parent.children.index(node.node_id)
                        if idx > 0:
                            prev_sibling_id = parent.children[idx - 1]
                            prev_sibling = context.file_node.nodes_map.get(prev_sibling_id)
                            if prev_sibling:
                                # Case A: Preceding sibling is directly the php_tag
                                if prev_sibling.node_type == "php_tag" and prev_sibling.get_text(source_bytes) == "<?=":
                                    return True, "echo", node_text
                                # Case B: Preceding sibling is text_interpolation ending with php_tag <?=
                                if prev_sibling.node_type == "text_interpolation":
                                    if prev_sibling.children:
                                        last_child_id = prev_sibling.children[-1]
                                        last_child = context.file_node.nodes_map.get(last_child_id)
                                        if last_child and last_child.node_type == "php_tag" and last_child.get_text(source_bytes) == "<?=":
                                            return True, "echo", node_text
                    except ValueError:
                        pass

        # Step 2: Exact or word-boundary text search for symbol trigger in node_text
        for trigger in triggers:
            if any(separator in trigger for separator in (".", "->", "::")):
                pattern = re.escape(trigger).replace(r"\-\>", r"\s*->\s*").replace(r"\:\:", r"\s*::\s*")
            else:
                pattern = r"(?<!\w)" + re.escape(trigger) + r"(?!\w)"
            if re.search(pattern, node_text):
                return True, trigger, node_text

        # Step 3: SymbolTable metadata search
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
