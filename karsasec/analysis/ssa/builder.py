"""SSABuilder module performing variable renaming and Phi node insertion on CFGs."""

from __future__ import annotations

from karsasec.analysis.cfg.models import CFG, CFGNodeType
from karsasec.analysis.ssa.models import PhiNode, SSAFunction, SSANode, SSAVar
from karsasec.ir.nodes import IRAssignment


class SSABuilder:
    """Transforms Control Flow Graphs (CFG) into Static Single Assignment (SSA) form."""

    def build_ssa(self, cfg: CFG) -> SSAFunction:
        """Converts a CFG into SSA form with versioned variables and Phi nodes."""
        ssa_func = SSAFunction(function_name=cfg.function_name, file_path=cfg.file_path)

        var_counters: dict[str, int] = {}
        var_stacks: dict[str, list[int]] = {}

        def get_new_version(name: str) -> SSAVar:
            v = var_counters.get(name, 0) + 1
            var_counters[name] = v
            if name not in var_stacks:
                var_stacks[name] = []
            var_stacks[name].append(v)
            return SSAVar(base_name=name, version=v)

        def get_current_version(name: str) -> SSAVar:
            if name in var_stacks and var_stacks[name]:
                return SSAVar(base_name=name, version=var_stacks[name][-1])
            return SSAVar(base_name=name, version=0)

        # Traverse nodes and rename variables
        for nid, node in cfg.nodes.items():
            if node.node_type == CFGNodeType.CONDITION and "Merge" in node.label:
                # Merge point -> Insert Phi node for tracked variables
                for var_name in list(var_counters.keys()):
                    target_var = get_new_version(var_name)
                    # Phi node consumes versions from incoming paths
                    op1 = SSAVar(base_name=var_name, version=target_var.version - 1)
                    op2 = SSAVar(base_name=var_name, version=target_var.version)
                    phi = PhiNode(target_var=target_var, operand_vars=[op1, op2], basic_block_id=nid)
                    ssa_func.phi_nodes.append(phi)
                    ssa_node = SSANode(
                        id=f"{nid}::phi::{var_name}",
                        line_number=node.line_number,
                        target=target_var,
                        phi_node=phi,
                        label=f"Φ({op1.ssa_name}, {op2.ssa_name})",
                    )
                    ssa_func.nodes.append(ssa_node)

            for stmt in node.statements:
                if isinstance(stmt, IRAssignment):
                    target_name = stmt.target.name if hasattr(stmt.target, "name") else str(stmt.target)
                    # Extract variables referenced in value_expression
                    use_vars: list[SSAVar] = []
                    for vname in var_counters:
                        if vname in str(stmt.value_expression):
                            use_vars.append(get_current_version(vname))

                    target_var = get_new_version(target_name)
                    ssa_node = SSANode(
                        id=stmt.id,
                        line_number=stmt.line_number,
                        target=target_var,
                        use_vars=use_vars,
                        label=f"{target_var.ssa_name} = {stmt.value_expression}",
                    )
                    ssa_func.nodes.append(ssa_node)

        return ssa_func
