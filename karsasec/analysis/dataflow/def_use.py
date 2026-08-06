"""Def-Use and Use-Def chain constructor."""

from __future__ import annotations

from karsasec.analysis.dataflow.models import DefUseChain, UseDefChain, VariableRef
from karsasec.analysis.ssa.models import SSAFunction


class DefUseBuilder:
    """Constructs Def-Use (definition -> uses) and Use-Def (use -> definitions) chains from SSA form."""

    def build_chains(self, ssa_func: SSAFunction) -> tuple[list[DefUseChain], list[UseDefChain]]:
        """Generates DefUseChain list and UseDefChain list."""
        def_map: dict[str, VariableRef] = {}
        use_map: dict[str, list[VariableRef]] = {}

        for node in ssa_func.nodes:
            if node.target:
                def_ref = VariableRef(
                    name=node.target.base_name,
                    ssa_version=node.target.version,
                    line_number=node.line_number,
                )
                def_map[node.target.ssa_name] = def_ref

            for use_var in node.use_vars:
                use_ref = VariableRef(
                    name=use_var.base_name,
                    ssa_version=use_var.version,
                    line_number=node.line_number,
                )
                if use_var.ssa_name not in use_map:
                    use_map[use_var.ssa_name] = []
                use_map[use_var.ssa_name].append(use_ref)

        def_use_chains: list[DefUseChain] = []
        use_def_chains: list[UseDefChain] = []

        for ssa_name, def_ref in def_map.items():
            uses = use_map.get(ssa_name, [])
            def_use_chains.append(DefUseChain(definition=def_ref, uses=uses))

            for use_ref in uses:
                use_def_chains.append(UseDefChain(use=use_ref, definitions=[def_ref]))

        return def_use_chains, use_def_chains
