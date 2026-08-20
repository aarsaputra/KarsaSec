"""CPGBuilder merging all analysis graph artifacts into a unified CPGGraph."""

from __future__ import annotations

import time

from karsasec.analysis.cfg.models import CFG
from karsasec.analysis.dataflow.models import DataFlowGraph
from karsasec.analysis.interprocedural.models import InterproceduralTaintGraph
from karsasec.analysis.ssa.models import SSAFunction
from karsasec.analysis.taint.models import TaintGraph
from karsasec.cpg.linking import NodeLinker
from karsasec.cpg.models import (
    CPGEdge,
    CPGGraph,
    CPGMetadata,
    CPGNode,
    EdgeType,
    NodeType,
    generate_stable_node_id,
)
from karsasec.ir.nodes import IRFunction
from karsasec.parser.ast_nodes import FileNode


class CPGBuilder:
    """Merges AST, IR, CFG, SSA, DataFlow, and Taint graphs into a unified CPGGraph."""

    def __init__(self) -> None:
        self.linker: NodeLinker = NodeLinker()

    def build_cpg(
        self,
        file_nodes: list[FileNode] | None = None,
        ir_functions: list[IRFunction] | None = None,
        cfgs: dict[str, CFG] | None = None,
        ssa_functions: dict[str, SSAFunction] | None = None,
        dfg_map: dict[str, DataFlowGraph] | None = None,
        taint_graphs: dict[str, TaintGraph] | None = None,
        itg: InterproceduralTaintGraph | None = None,
        project_name: str = "KarsaSecProject",
    ) -> CPGGraph:
        start_time = time.time()
        metadata = CPGMetadata(project_name=project_name)
        graph = CPGGraph(metadata=metadata)

        languages = set()

        # 1. Add AST Nodes
        if file_nodes:
            for fn in file_nodes:
                languages.add(fn.language)
                nid = generate_stable_node_id(fn.file_path, fn.file_path, 1, 0, NodeType.AST)
                node = CPGNode(
                    id=nid,
                    node_type=NodeType.AST,
                    label=f"File:{fn.file_path}",
                    file_path=fn.file_path,
                    line_number=1,
                    language=fn.language,
                    labels=("File", fn.language),
                )
                graph.add_node(node)

        # 2. Add IR Function & Call Nodes
        if ir_functions:
            for ir_f in ir_functions:
                languages.add(ir_f.language)
                nid = generate_stable_node_id(ir_f.file_path, ir_f.name, ir_f.line_number, 0, NodeType.FUNCTION)
                node = CPGNode(
                    id=nid,
                    node_type=NodeType.FUNCTION,
                    label=f"Function:{ir_f.name}",
                    file_path=ir_f.file_path,
                    line_number=ir_f.line_number,
                    language=ir_f.language,
                    labels=("Function", "Code"),
                    attributes={"function_name": ir_f.name},
                )
                graph.add_node(node)

        # 3. Add CFG Nodes & CFG_FLOW Edges
        if cfgs:
            for fn_name, cfg in cfgs.items():
                node_id_map = {}
                for cfg_n in cfg.nodes.values():
                    nid = generate_stable_node_id(
                        cfg.file_path, f"{fn_name}::{cfg_n.id}", cfg_n.line_number, 0, NodeType.CFG
                    )
                    cpg_n = CPGNode(
                        id=nid,
                        node_type=NodeType.CFG,
                        label=cfg_n.label,
                        file_path=cfg.file_path,
                        line_number=cfg_n.line_number,
                        language=getattr(cfg, "language", "Generic"),
                        labels=("CFGNode", cfg_n.node_type.value),
                        attributes={"cfg_id": cfg_n.id, "function_name": fn_name},
                    )
                    graph.add_node(cpg_n)
                    node_id_map[cfg_n.id] = nid

                for edge in cfg.edges:
                    src_id = getattr(edge, "source_id", getattr(edge, "source", None))
                    tgt_id = getattr(edge, "target_id", getattr(edge, "target", None))
                    if src_id in node_id_map and tgt_id in node_id_map:
                        graph.add_edge(
                            CPGEdge(node_id_map[src_id], node_id_map[tgt_id], EdgeType.CFG_FLOW, {"origin": "CFG"})
                        )

        # 4. Add SSA Nodes
        if ssa_functions:
            for fn_name, ssa in ssa_functions.items():
                for ssa_n in ssa.nodes:
                    var_name = (
                        ssa_n.target_var.base_name if hasattr(ssa_n, "target_var") and ssa_n.target_var else "ssa_var"
                    )
                    version = ssa_n.target_var.version if hasattr(ssa_n, "target_var") and ssa_n.target_var else 0
                    nid = generate_stable_node_id("ssa", f"{fn_name}::{ssa_n.id}", ssa_n.line_number, 0, NodeType.SSA)
                    cpg_n = CPGNode(
                        id=nid,
                        node_type=NodeType.SSA,
                        label=f"SSA:{var_name}_{version}",
                        line_number=ssa_n.line_number,
                        labels=("SSA", "Variable"),
                        attributes={"variable": var_name, "version": version, "function_name": fn_name},
                    )
                    graph.add_node(cpg_n)

        # 5. Add DataFlow Nodes & DATAFLOW Edges
        if dfg_map:
            for fn_name, dfg in dfg_map.items():
                dfg_id_map = {}
                for df_n in dfg.nodes.values():
                    vname = getattr(df_n, "variable_name", getattr(df_n, "var_name", df_n.label))
                    nid = generate_stable_node_id(
                        "dfg", f"{fn_name}::{df_n.id}", df_n.line_number, 0, NodeType.DATAFLOW
                    )
                    cpg_n = CPGNode(
                        id=nid,
                        node_type=NodeType.DATAFLOW,
                        label=df_n.label,
                        line_number=df_n.line_number,
                        labels=("DataFlow", vname),
                        attributes={"variable": vname, "function_name": fn_name},
                    )
                    graph.add_node(cpg_n)
                    dfg_id_map[df_n.id] = nid

                for edge in dfg.edges:
                    if edge.source_id in dfg_id_map and edge.target_id in dfg_id_map:
                        graph.add_edge(
                            CPGEdge(
                                dfg_id_map[edge.source_id],
                                dfg_id_map[edge.target_id],
                                EdgeType.DATAFLOW,
                                {"origin": "DFG"},
                            )
                        )

        # 6. Add Taint Nodes & TAINT Edges
        if taint_graphs:
            for fn_name, tg in taint_graphs.items():
                tg_id_map = {}
                for t_n in tg.nodes.values():
                    nid = generate_stable_node_id("taint", f"{fn_name}::{t_n.id}", t_n.line_number, 0, NodeType.TAINT)
                    cpg_n = CPGNode(
                        id=nid,
                        node_type=NodeType.TAINT,
                        label=t_n.label,
                        line_number=t_n.line_number,
                        labels=("Taint", t_n.state.value),
                        attributes={"state": t_n.state.value, "function_name": fn_name},
                    )
                    graph.add_node(cpg_n)
                    tg_id_map[t_n.id] = nid

                for edge in tg.edges:
                    if edge.source_id in tg_id_map and edge.target_id in tg_id_map:
                        graph.add_edge(
                            CPGEdge(
                                tg_id_map[edge.source_id],
                                tg_id_map[edge.target_id],
                                EdgeType.TAINT,
                                {"confidence": edge.confidence, "origin": "TaintEngine"},
                            )
                        )

        # 7. Add Interprocedural Call Chains
        if itg:
            for path in itg.vulnerable_paths:
                for cs in path.call_chain:
                    src_id = generate_stable_node_id(
                        "call", f"{cs.caller_id}->{cs.callee_name}", cs.line_number, 0, NodeType.CALLSITE
                    )
                    cpg_n = CPGNode(
                        id=src_id,
                        node_type=NodeType.CALLSITE,
                        label=f"Call:{cs.callee_name}",
                        line_number=cs.line_number,
                        labels=("CallSite", cs.callee_name),
                        attributes={"caller": cs.caller_id, "callee": cs.callee_name},
                    )
                    graph.add_node(cpg_n)

        # 8. Perform explicit cross-representation linking
        self.linker.link_representation_layers(graph)

        metadata.languages = sorted(list(languages)) if languages else ["Generic"]
        metadata.duration_seconds = round(time.time() - start_time, 4)
        metadata.node_count = len(graph.nodes)
        metadata.edge_count = len(graph.edges)

        return graph
