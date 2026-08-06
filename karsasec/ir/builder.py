"""Builder converting language-specific AST nodes into Generic IR representation."""

from karsasec.ir.nodes import IRAssign, IRBlock, IRCall, IRNode, IRVar


class IRBuilder:
    """Translates language-specific AST nodes into Generic IR nodes."""

    def build_call(self, node_id: str, callee_name: str, line: int = 0) -> IRCall:
        return IRCall(node_id=node_id, callee=callee_name, line=line)

    def build_assign(self, node_id: str, target_name: str, value_node: IRNode, line: int = 0) -> IRAssign:
        target_var = IRVar(node_id=f"var_{target_name}", name=target_name, line=line)
        return IRAssign(node_id=node_id, target=target_var, value=value_node, line=line)

    def build_block(self, node_id: str, statements: list) -> IRBlock:
        return IRBlock(node_id=node_id, statements=statements)


ir_builder = IRBuilder()
