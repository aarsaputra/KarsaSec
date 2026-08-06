"""Stateless ASTVisitor base class implementing class-based dynamic dispatch."""

from karsasec.parser.ast.context import VisitorContext
from karsasec.parser.ast_nodes import ASTNode


class ASTVisitor:
    """Stateless Visitor pattern base class for inspecting AST nodes."""

    def visit(self, node: ASTNode, context: VisitorContext) -> None:
        """Dispatches node inspection based on class type or node_type."""
        class_name = node.__class__.__name__
        method_name = f"visit_{class_name}"
        visitor_method = getattr(self, method_name, None)

        if not visitor_method:
            # Fallback to node_type dynamic name (e.g., visit_call, visit_import)
            method_name_alt = f"visit_{node.node_type}"
            visitor_method = getattr(self, method_name_alt, self.default_visit)

        visitor_method(node, context)

    def default_visit(self, node: ASTNode, context: VisitorContext) -> None:
        """Fallback visit handler called when no type-specific visitor method is matched."""
        pass
