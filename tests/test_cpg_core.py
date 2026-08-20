from __future__ import annotations

import tempfile
from pathlib import Path

from karsasec.analysis.cfg.builder import CFGBuilder
from karsasec.analysis.dataflow.builder import DataFlowBuilder
from karsasec.analysis.interprocedural import InterproceduralTaintEngine
from karsasec.analysis.ssa.builder import SSABuilder
from karsasec.analysis.taint import IntraproceduralTaintEngine
from karsasec.core.pipeline.context import PassContext
from karsasec.core.pipeline.pass_manager import PassManager
from karsasec.cpg import (
    CPGBuilder,
    CPGEdge,
    CPGGraph,
    CPGNode,
    CPGPass,
    CPGQuery,
    CPGSerializer,
    CPGValidator,
    CPGVisitor,
    EdgeType,
    GraphDiff,
    GraphIndex,
    GraphTraversal,
    NodeType,
    generate_stable_node_id,
)
from karsasec.ir.nodes import IRAssignment, IRCall, IRFunction


def test_stable_node_id_deterministic() -> None:
    id1 = generate_stable_node_id("app.py", "main", 10, 5, NodeType.FUNCTION)
    id2 = generate_stable_node_id("app.py", "main", 10, 5, NodeType.FUNCTION)
    id3 = generate_stable_node_id("app.py", "other", 10, 5, NodeType.FUNCTION)

    assert id1 == id2
    assert id1 != id3
    assert len(id1) == 16


def test_cpg_builder_and_linking() -> None:
    fn = IRFunction(
        id="app.py::main::1",
        line_number=1,
        file_path="app.py",
        language="Python",
        name="main",
    )
    assign = IRAssignment(
        id="app.py::assign::2",
        line_number=2,
        file_path="app.py",
        language="Python",
        target="user",
        value_expression="request.args['user']",
    )
    call = IRCall(
        id="app.py::call::3",
        line_number=3,
        file_path="app.py",
        language="Python",
        callee_name="db.execute",
        arguments=["user"],
    )
    fn.body_statements = [assign, call]

    cfg = CFGBuilder().build_cfg(fn)
    ssa = SSABuilder().build_ssa(cfg)
    dfg = DataFlowBuilder().build_dataflow_graph(cfg, ssa)
    tg = IntraproceduralTaintEngine().analyze_function(cfg, ssa, dfg)
    itg = InterproceduralTaintEngine().analyze_program({"main": tg}, {"main": dfg})

    cpg_builder = CPGBuilder()
    cpg = cpg_builder.build_cpg(
        ir_functions=[fn],
        cfgs={"main": cfg},
        ssa_functions={"main": ssa},
        dfg_map={"main": dfg},
        taint_graphs={"main": tg},
        itg=itg,
        project_name="TestProject",
    )

    assert len(cpg.nodes) > 0
    assert len(cpg.edges) > 0
    assert cpg.metadata.project_name == "TestProject"


def test_graph_index_lookups() -> None:
    cpg = CPGGraph()
    n1 = CPGNode(
        id="n1",
        node_type=NodeType.FUNCTION,
        label="main",
        file_path="app.py",
        line_number=5,
        labels=("Function", "Code"),
        attributes={"function_name": "main"},
    )
    n2 = CPGNode(id="n2", node_type=NodeType.CFG, label="stmt", file_path="app.py", line_number=10, labels=("CFGNode",))

    cpg.add_node(n1)
    cpg.add_node(n2)

    idx = GraphIndex(cpg)
    assert idx.get_by_id("n1") == n1
    assert len(idx.get_by_file("app.py")) == 2
    assert len(idx.get_by_function("main")) == 1
    assert len(idx.get_by_label("Function")) == 1
    assert len(idx.get_by_type(NodeType.CFG)) == 1


def test_cpg_validator() -> None:
    cpg = CPGGraph()
    n1 = CPGNode(id="n1", node_type=NodeType.AST, label="file")
    n2 = CPGNode(id="n2", node_type=NodeType.IR, label="func")

    cpg.add_node(n1)
    cpg.add_node(n2)
    cpg.add_edge(CPGEdge("n1", "n2", EdgeType.REPRESENTS))
    cpg.add_edge(CPGEdge("n1", "non_existent", EdgeType.CFG_FLOW))

    validator = CPGValidator()
    issues = validator.validate(cpg)

    assert any(i.issue_type == "BROKEN_EDGE_TARGET" for i in issues)


def test_cpg_serializer_and_gzip() -> None:
    cpg = CPGGraph()
    n1 = CPGNode(id="n1", node_type=NodeType.FUNCTION, label="main")
    cpg.add_node(n1)

    serializer = CPGSerializer()

    with tempfile.NamedTemporaryFile(suffix=".cpg.gz", delete=False) as tmp:
        p = Path(tmp.name)
        serializer.save_compressed(cpg, p)
        loaded = serializer.load_compressed(p)
        assert len(loaded.nodes) == 1
        assert loaded.nodes["n1"].label == "main"
        p.unlink()


def test_graph_traversal_and_visitor() -> None:
    cpg = CPGGraph()
    n1 = CPGNode(id="n1", node_type=NodeType.FUNCTION, label="main")
    n2 = CPGNode(id="n2", node_type=NodeType.CFG, label="stmt")
    cpg.add_node(n1)
    cpg.add_node(n2)
    cpg.add_edge(CPGEdge("n1", "n2", EdgeType.CFG_FLOW))

    trav = GraphTraversal(cpg)
    dfs_nodes = trav.dfs("n1")
    assert len(dfs_nodes) == 2
    assert trav.reachability("n1", "n2") is True
    assert trav.reachability("n2", "n1") is False

    visited_count = [0]

    class MockVisitor(CPGVisitor):
        def visit(self, node: CPGNode) -> None:
            visited_count[0] += 1

    MockVisitor().walk(cpg)
    assert visited_count[0] == 2


def test_graph_diff() -> None:
    cpg1 = CPGGraph()
    n1 = CPGNode(id="n1", node_type=NodeType.FUNCTION, label="main")
    cpg1.add_node(n1)

    cpg2 = CPGGraph()
    n1_mod = CPGNode(id="n1", node_type=NodeType.FUNCTION, label="main_mod")
    n2 = CPGNode(id="n2", node_type=NodeType.CFG, label="stmt")
    cpg2.add_node(n1_mod)
    cpg2.add_node(n2)

    diff = GraphDiff().compare(cpg1, cpg2)
    assert len(diff.added_nodes) == 1
    assert len(diff.modified_nodes) == 1


def test_fluent_query_foundation() -> None:
    cpg = CPGGraph()
    n1 = CPGNode(id="n1", node_type=NodeType.FUNCTION, label="main", language="Python")
    n2 = CPGNode(id="n2", node_type=NodeType.CFG, label="stmt", language="Python")
    cpg.add_node(n1)
    cpg.add_node(n2)
    cpg.add_edge(CPGEdge("n1", "n2", EdgeType.CFG_FLOW))

    q = CPGQuery(cpg)
    res = q.find_nodes(NodeType.FUNCTION).where(language="Python").execute()
    assert len(res) == 1
    assert res[0].id == "n1"

    out = CPGQuery(cpg).find_nodes(NodeType.FUNCTION).outgoing(EdgeType.CFG_FLOW).execute()
    assert len(out) == 1
    assert out[0].id == "n2"


def test_cpg_pass_integration() -> None:
    ir_func = IRFunction(
        id="app.py::foo::1",
        line_number=1,
        file_path="app.py",
        language="Python",
        name="foo",
    )
    cfg = CFGBuilder().build_cfg(ir_func)
    ssa = SSABuilder().build_ssa(cfg)
    dfg = DataFlowBuilder().build_dataflow_graph(cfg, ssa)
    tg = IntraproceduralTaintEngine().analyze_function(cfg, ssa, dfg)

    context = PassContext()
    context.artifact_store.store("CFG", {"foo": cfg})
    context.artifact_store.store("SSA", {"foo": ssa})
    context.artifact_store.store("DataFlowGraph", {"foo": dfg})
    context.artifact_store.store("TaintGraph", {"foo": tg})

    manager = PassManager()
    manager.register_pass(CPGPass())

    final_context = manager.run_passes(context)
    assert final_context.artifact_store.has("CPGGraph")
    assert final_context.artifact_store.has("CPGIndex")
    assert final_context.artifact_store.has("CPGMetadata")
