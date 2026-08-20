"""Query Executor executing Execution Plans against CPG in a stateless manner."""

from __future__ import annotations

import time

from karsasec.cpg.index import GraphIndex
from karsasec.cpg.models import CPGGraph, CPGNode, NodeType
from karsasec.query.ast import ExecutionPlanNode, PredicateNode
from karsasec.query.context import ExecutionContext
from karsasec.query.predicates import PredicateEngine
from karsasec.query.traversal_engine import MultiHopTraversalEngine


class QueryExecutor:
    """Stateless Query Executor evaluating ExecutionPlanNode against CPGGraph."""

    def execute(
        self,
        plan: ExecutionPlanNode,
        graph: CPGGraph,
        index: GraphIndex | None = None,
        context: ExecutionContext | None = None,
    ) -> list[CPGNode]:
        if context is None:
            context = ExecutionContext()

        start_time = time.time()
        idx = index or GraphIndex(graph)
        traversal = MultiHopTraversalEngine(graph)

        nodes = self._evaluate_plan_node(plan, graph, idx, traversal, context)

        context.metrics.execution_time_ms = (time.time() - start_time) * 1000.0
        return nodes

    def _evaluate_plan_node(
        self,
        plan: ExecutionPlanNode,
        graph: CPGGraph,
        index: GraphIndex,
        traversal: MultiHopTraversalEngine,
        context: ExecutionContext,
    ) -> list[CPGNode]:
        context.check_timeout()

        if plan.op_type == "INDEX_LOOKUP":
            field = str(plan.params.get("index_field", ""))
            val = str(plan.params.get("index_value", ""))
            context.metrics.nodes_scanned += 1
            if field == "id":
                n = index.get_by_id(val)
                return [n] if n else []
            if field == "file_path":
                return index.get_by_file(val)
            if field == "function_name":
                return index.get_by_function(val)
            if field == "label":
                return index.get_by_label(val)
            return [n for n in graph.nodes.values() if PredicateEngine._extract_field(field, n) == val]

        if plan.op_type == "SCAN":
            target_label = str(plan.params.get("target_label", ""))
            context.metrics.nodes_scanned += len(graph.nodes)
            if target_label and hasattr(NodeType, target_label):
                return index.get_by_type(NodeType[target_label])
            if target_label:
                return [
                    n for n in graph.nodes.values() if target_label in n.labels or n.node_type.value == target_label
                ]
            return list(graph.nodes.values())

        if not plan.children:
            return []

        input_nodes = self._evaluate_plan_node(plan.children[0], graph, index, traversal, context)

        if plan.op_type == "FILTER":
            p_dict = plan.params.get("predicate")
            if not p_dict:
                return input_nodes
            pred = PredicateNode.from_dict(p_dict)
            return [n for n in input_nodes if PredicateEngine.evaluate(pred, n)]

        if plan.op_type == "TRAVERSE":
            direction = str(plan.params.get("direction", "OUTGOING"))
            edge_type = str(plan.params.get("edge_type", ""))
            target_type = str(plan.params.get("target_type", ""))
            result: list[CPGNode] = []

            for src in input_nodes:
                context.check_timeout()
                edges = (
                    graph.get_outgoing_edges(src.id) if direction == "OUTGOING" else graph.get_incoming_edges(src.id)
                )
                context.metrics.edges_traversed += len(edges)

                for e in edges:
                    if edge_type and e.edge_type.value != edge_type and e.edge_type.name != edge_type:
                        continue
                    tgt_id = e.target_id if direction == "OUTGOING" else e.source_id
                    tgt_node = graph.nodes.get(tgt_id)
                    if tgt_node:
                        if (
                            target_type
                            and target_type not in tgt_node.labels
                            and tgt_node.node_type.value != target_type
                        ):
                            continue
                        result.append(tgt_node)

            return result

        if plan.op_type == "LIMIT":
            limit = int(plan.params.get("limit", 0))
            return input_nodes[:limit] if limit > 0 else input_nodes

        if plan.op_type == "PROJECTION":
            return input_nodes

        return input_nodes
