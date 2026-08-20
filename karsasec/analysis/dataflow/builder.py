"""DataFlowBuilder orchestrating CFG, SSA, Reaching Definitions, and Def-Use chains."""

from __future__ import annotations

from karsasec.analysis.cfg.models import CFG
from karsasec.analysis.dataflow.def_use import DefUseBuilder
from karsasec.analysis.dataflow.models import DataFlowGraph, DataFlowNode, VariableRef
from karsasec.analysis.dataflow.propagation import ConstantPropagation
from karsasec.analysis.dataflow.reaching_definitions import ReachingDefinitionsAnalysis
from karsasec.analysis.ssa.models import SSAFunction


class DataFlowBuilder:
    """Orchestrates Data Flow Analysis pipelines into unified DataFlowGraph objects."""

    def build_dataflow_graph(self, cfg: CFG, ssa_func: SSAFunction) -> DataFlowGraph:
        """Constructs a DataFlowGraph for a function."""
        dfg = DataFlowGraph(function_name=cfg.function_name, file_path=cfg.file_path)

        # Step 1: Reaching Definitions Analysis
        rd_analysis = ReachingDefinitionsAnalysis(cfg, ssa_func)
        rd_analysis.analyze()

        # Step 2: Def-Use and Use-Def Chains
        def_use_builder = DefUseBuilder()
        def_use_chains, use_def_chains = def_use_builder.build_chains(ssa_func)
        dfg.def_use_chains = def_use_chains
        dfg.use_def_chains = use_def_chains

        # Step 3: Constant Propagation
        const_prop = ConstantPropagation()
        dfg.constant_values = const_prop.propagate(ssa_func)

        # Step 4: Populate DataFlowGraph Nodes & Edges
        for nid, cfg_node in cfg.nodes.items():
            reaching = rd_analysis.get_reaching_definitions(nid)

            node_defs: list[VariableRef] = []
            node_uses: list[VariableRef] = []

            for snode in ssa_func.nodes:
                if snode.id.startswith(nid):
                    if snode.target:
                        node_defs.append(
                            VariableRef(
                                name=snode.target.base_name,
                                ssa_version=snode.target.version,
                                line_number=snode.line_number,
                            )
                        )
                    for uvar in snode.use_vars:
                        node_uses.append(
                            VariableRef(
                                name=uvar.base_name,
                                ssa_version=uvar.version,
                                line_number=snode.line_number,
                            )
                        )

            df_node = DataFlowNode(
                id=f"{nid}::df",
                statement_id=nid,
                line_number=cfg_node.line_number,
                definitions=node_defs or reaching,
                uses=node_uses,
                label=cfg_node.label,
            )
            dfg.add_node(df_node)

        # Step 5: Connect data dependence edges based on Def-Use chains
        for duc in def_use_chains:
            for use in duc.uses:
                src_ids = [
                    nid
                    for nid, n in dfg.nodes.items()
                    if any(d.ssa_name == duc.definition.ssa_name for d in n.definitions)
                ]
                tgt_ids = [nid for nid, n in dfg.nodes.items() if any(u.ssa_name == use.ssa_name for u in n.uses)]
                for src in src_ids:
                    for tgt in tgt_ids:
                        dfg.add_edge(source_id=src, target_id=tgt, var_name=duc.definition.name)

        return dfg
