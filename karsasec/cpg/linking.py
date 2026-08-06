"""NodeLinker connecting representations across AST, IR, CFG, SSA, DataFlow, and Taint layers using explicit CPGEdges."""

from __future__ import annotations

from karsasec.cpg.models import CPGEdge, CPGGraph, CPGNode, EdgeType, NodeType


class NodeLinker:
    """Connects nodes across representation layers using typed CPG edges."""

    def link_representation_layers(self, graph: CPGGraph) -> int:
        """Links AST -> IR -> CFG -> SSA -> DataFlow -> Taint nodes in graph."""
        edges_added = 0

        # Group nodes by file_path & line_number
        location_map: dict[tuple[str, int], list[CPGNode]] = {}
        for node in graph.nodes.values():
            if node.file_path:
                location_map.setdefault((node.file_path, node.line_number), []).append(node)

        for nodes in location_map.values():
            ast_nodes = [n for n in nodes if n.node_type == NodeType.AST]
            ir_nodes = [n for n in nodes if n.node_type == NodeType.IR]
            cfg_nodes = [n for n in nodes if n.node_type == NodeType.CFG]
            ssa_nodes = [n for n in nodes if n.node_type == NodeType.SSA]
            df_nodes = [n for n in nodes if n.node_type == NodeType.DATAFLOW]
            taint_nodes = [n for n in nodes if n.node_type == NodeType.TAINT]

            # Link AST -> IR
            for ast_n in ast_nodes:
                for ir_n in ir_nodes:
                    graph.add_edge(CPGEdge(ast_n.id, ir_n.id, EdgeType.REPRESENTS, {"origin": "NodeLinker"}))
                    edges_added += 1

            # Link IR -> CFG
            for ir_n in ir_nodes:
                for cfg_n in cfg_nodes:
                    graph.add_edge(CPGEdge(ir_n.id, cfg_n.id, EdgeType.LOWERED_TO, {"origin": "NodeLinker"}))
                    edges_added += 1

            # Link CFG -> SSA
            for cfg_n in cfg_nodes:
                for ssa_n in ssa_nodes:
                    graph.add_edge(CPGEdge(cfg_n.id, ssa_n.id, EdgeType.SSA_VERSION, {"origin": "NodeLinker"}))
                    edges_added += 1

            # Link SSA -> DataFlow
            for ssa_n in ssa_nodes:
                for df_n in df_nodes:
                    graph.add_edge(CPGEdge(ssa_n.id, df_n.id, EdgeType.DATAFLOW, {"origin": "NodeLinker"}))
                    edges_added += 1

            # Link DataFlow -> Taint
            for df_n in df_nodes:
                for t_n in taint_nodes:
                    graph.add_edge(CPGEdge(df_n.id, t_n.id, EdgeType.TAINT, {"origin": "NodeLinker"}))
                    edges_added += 1

        return edges_added
