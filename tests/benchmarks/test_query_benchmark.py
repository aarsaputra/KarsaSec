"""Benchmark suite for Query Planner, Optimizer, Executor, Traversal, and Cache."""

from __future__ import annotations

import time

from karsasec.cpg import CPGEdge, CPGGraph, CPGNode, EdgeType, NodeType
from karsasec.query import (
    ExecutionContext,
    Function,
    MultiHopTraversalEngine,
    QueryExecutor,
    QueryOptimizer,
    QueryPlanner,
)


def test_planner_and_optimizer_benchmark() -> None:
    planner = QueryPlanner()
    optimizer = QueryOptimizer()

    start = time.time()
    for _ in range(100):
        q_ast = Function("test_func").where(language="python").outgoing("CALL").build()
        raw_plan = planner.create_plan(q_ast)
        opt_plan = optimizer.optimize(raw_plan)
        assert opt_plan is not None

    elapsed_ms = (time.time() - start) * 1000.0
    avg_plan_opt_ms = elapsed_ms / 100.0

    assert avg_plan_opt_ms < 20.0, f"Planner + Optimizer average time ({avg_plan_opt_ms:.2f}ms) exceeded 20ms target!"


def test_executor_and_traversal_benchmark() -> None:
    graph = CPGGraph()
    # Build 10,000 node graph
    for i in range(10000):
        node = CPGNode(
            id=f"node_{i}",
            node_type=NodeType.CFG if i % 2 == 0 else NodeType.FUNCTION,
            label=f"func_{i}" if i % 2 == 1 else f"stmt_{i}",
            line_number=i,
            attributes={"function_name": f"func_{i}"},
        )
        graph.add_node(node)

    for i in range(9999):
        graph.add_edge(CPGEdge(f"node_{i}", f"node_{i + 1}", EdgeType.CFG_FLOW))

    planner = QueryPlanner()
    optimizer = QueryOptimizer()
    executor = QueryExecutor()

    q_ast = Function("func_1").build()
    plan = optimizer.optimize(planner.create_plan(q_ast))

    start = time.time()
    ctx = ExecutionContext()
    results = executor.execute(plan, graph, context=ctx)
    elapsed_ms = (time.time() - start) * 1000.0

    assert elapsed_ms < 100.0, f"Executor average time ({elapsed_ms:.2f}ms) exceeded 100ms target on 10K nodes!"

    traversal = MultiHopTraversalEngine(graph)
    start_tr = time.time()
    reach = traversal.reachability("node_0", "node_500", max_depth=600)
    elapsed_tr_ms = (time.time() - start_tr) * 1000.0

    assert reach is True
    assert elapsed_tr_ms < 50.0
