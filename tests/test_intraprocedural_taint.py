from __future__ import annotations

from karsasec.analysis.cfg.builder import CFGBuilder
from karsasec.analysis.dataflow.builder import DataFlowBuilder
from karsasec.analysis.ssa.builder import SSABuilder
from karsasec.analysis.taint import (
    IntraproceduralTaintEngine,
    SanitizerRegistry,
    SinkRegistry,
    SourceRegistry,
    TaintPass,
)
from karsasec.core.pipeline.context import PassContext
from karsasec.core.pipeline.pass_manager import PassManager
from karsasec.ir.nodes import IRAssignment, IRCall, IRFunction


def test_registries() -> None:
    sources = SourceRegistry()
    sinks = SinkRegistry()
    sanitizers = SanitizerRegistry()

    assert sources.is_source("request.args['id']", "Python") is True
    assert sinks.is_sink("db.execute(query)") is True
    assert sanitizers.is_sanitizer("html.escape(user_input)") is True


def test_unsanitized_taint_flow() -> None:
    ir_func = IRFunction(
        id="app.py::vulnerable_sqli::1",
        line_number=1,
        file_path="app.py",
        language="Python",
        name="vulnerable_sqli",
    )

    source_assign = IRAssignment(
        id="app.py::assign::2",
        line_number=2,
        file_path="app.py",
        language="Python",
        target="raw_id",
        value_expression="request.args['id']",
    )

    prop_assign = IRAssignment(
        id="app.py::assign::3",
        line_number=3,
        file_path="app.py",
        language="Python",
        target="query_id",
        value_expression="raw_id",
    )

    sink_call = IRCall(
        id="app.py::call::4",
        line_number=4,
        file_path="app.py",
        language="Python",
        callee_name="db.execute",
        arguments=["query_id"],
    )

    ir_func.body_statements = [source_assign, prop_assign, sink_call]

    cfg = CFGBuilder().build_cfg(ir_func)
    ssa_func = SSABuilder().build_ssa(cfg)
    dfg = DataFlowBuilder().build_dataflow_graph(cfg, ssa_func)

    engine = IntraproceduralTaintEngine()
    taint_graph = engine.analyze_function(cfg, ssa_func, dfg)

    assert len(taint_graph.vulnerable_paths) >= 1
    assert taint_graph.vulnerable_paths[0].is_vulnerable is True


def test_sanitizer_cancels_taint_flow() -> None:
    ir_func = IRFunction(
        id="app.py::safe_sqli::1",
        line_number=1,
        file_path="app.py",
        language="Python",
        name="safe_sqli",
    )

    source_assign = IRAssignment(
        id="app.py::assign::2",
        line_number=2,
        file_path="app.py",
        language="Python",
        target="raw_id",
        value_expression="request.args['id']",
    )

    sanitizer_assign = IRAssignment(
        id="app.py::assign::3",
        line_number=3,
        file_path="app.py",
        language="Python",
        target="clean_id",
        value_expression="escape(raw_id)",
    )

    sink_call = IRCall(
        id="app.py::call::4",
        line_number=4,
        file_path="app.py",
        language="Python",
        callee_name="db.execute",
        arguments=["clean_id"],
    )

    ir_func.body_statements = [source_assign, sanitizer_assign, sink_call]

    cfg = CFGBuilder().build_cfg(ir_func)
    ssa_func = SSABuilder().build_ssa(cfg)
    dfg = DataFlowBuilder().build_dataflow_graph(cfg, ssa_func)

    engine = IntraproceduralTaintEngine()
    taint_graph = engine.analyze_function(cfg, ssa_func, dfg)

    assert len(taint_graph.vulnerable_paths) == 0
    assert len(taint_graph.safe_paths) >= 1
    assert taint_graph.safe_paths[0].is_vulnerable is False


def test_taint_pass_pipeline_integration() -> None:
    ir_func = IRFunction(
        id="app.py::run::1",
        line_number=1,
        file_path="app.py",
        language="Python",
        name="run",
    )

    cfg = CFGBuilder().build_cfg(ir_func)
    ssa_func = SSABuilder().build_ssa(cfg)
    dfg = DataFlowBuilder().build_dataflow_graph(cfg, ssa_func)

    context = PassContext()
    context.artifact_store.store("CFG", {"run": cfg})
    context.artifact_store.store("SSA", {"run": ssa_func})
    context.artifact_store.store("DataFlowGraph", {"run": dfg})

    manager = PassManager()
    manager.register_pass(TaintPass())

    final_context = manager.run_passes(context)
    assert final_context.artifact_store.has("TaintGraph")
    taint_graphs = final_context.artifact_store.get("TaintGraph")
    assert "run" in taint_graphs
