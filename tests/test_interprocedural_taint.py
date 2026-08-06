from __future__ import annotations

from karsasec.analysis.cfg.builder import CFGBuilder
from karsasec.analysis.dataflow.builder import DataFlowBuilder
from karsasec.analysis.interprocedural import (
    InterproceduralTaintEngine,
    InterproceduralTaintPass,
    SummaryCache,
)
from karsasec.analysis.ssa.builder import SSABuilder
from karsasec.analysis.taint import IntraproceduralTaintEngine
from karsasec.core.pipeline.context import PassContext
from karsasec.core.pipeline.pass_manager import PassManager
from karsasec.ir.nodes import IRAssignment, IRCall, IRFunction


def test_interprocedural_helper_chain() -> None:
    # Caller: main()
    caller_fn = IRFunction(
        id="app.py::main::1",
        line_number=1,
        file_path="app.py",
        language="Python",
        name="main",
    )
    src_assign = IRAssignment(
        id="app.py::assign::2",
        line_number=2,
        file_path="app.py",
        language="Python",
        target="user_id",
        value_expression="request.args['id']",
    )
    helper_call = IRCall(
        id="app.py::call::3",
        line_number=3,
        file_path="app.py",
        language="Python",
        callee_name="query_db",
        arguments=["user_id"],
    )
    caller_fn.body_statements = [src_assign, helper_call]

    # Callee: query_db()
    callee_fn = IRFunction(
        id="app.py::query_db::10",
        line_number=10,
        file_path="app.py",
        language="Python",
        name="query_db",
    )
    sink_call = IRCall(
        id="app.py::call::11",
        line_number=11,
        file_path="app.py",
        language="Python",
        callee_name="db.execute",
        arguments=["sql"],
    )
    callee_fn.body_statements = [sink_call]

    cfg_main = CFGBuilder().build_cfg(caller_fn)
    cfg_helper = CFGBuilder().build_cfg(callee_fn)

    ssa_main = SSABuilder().build_ssa(cfg_main)
    ssa_helper = SSABuilder().build_ssa(cfg_helper)

    dfg_main = DataFlowBuilder().build_dataflow_graph(cfg_main, ssa_main)
    dfg_helper = DataFlowBuilder().build_dataflow_graph(cfg_helper, ssa_helper)

    intra_engine = IntraproceduralTaintEngine()
    tg_main = intra_engine.analyze_function(cfg_main, ssa_main, dfg_main)
    tg_helper = intra_engine.analyze_function(cfg_helper, ssa_helper, dfg_helper)

    inter_engine = InterproceduralTaintEngine()
    itg = inter_engine.analyze_program(
        taint_graphs={"main": tg_main, "query_db": tg_helper},
        dfg_map={"main": dfg_main, "query_db": dfg_helper},
    )

    assert len(itg.function_summaries) == 2
    assert len(itg.vulnerable_paths) >= 1
    assert itg.vulnerable_paths[0].source_func == "main"
    assert itg.vulnerable_paths[0].sink_func == "query_db"


def test_interprocedural_sanitizer_chain() -> None:
    # Caller: safe_main()
    caller_fn = IRFunction(
        id="app.py::safe_main::1",
        line_number=1,
        file_path="app.py",
        language="Python",
        name="safe_main",
    )
    src_assign = IRAssignment(
        id="app.py::assign::2",
        line_number=2,
        file_path="app.py",
        language="Python",
        target="user_id",
        value_expression="request.args['id']",
    )
    san_call = IRCall(
        id="app.py::call::3",
        line_number=3,
        file_path="app.py",
        language="Python",
        callee_name="safe_query_db",
        arguments=["user_id"],
    )
    caller_fn.body_statements = [src_assign, san_call]

    # Callee: safe_query_db()
    callee_fn = IRFunction(
        id="app.py::safe_query_db::10",
        line_number=10,
        file_path="app.py",
        language="Python",
        name="safe_query_db",
    )
    san_assign = IRAssignment(
        id="app.py::assign::11",
        line_number=11,
        file_path="app.py",
        language="Python",
        target="clean_id",
        value_expression="escape(sql)",
    )
    sink_call = IRCall(
        id="app.py::call::12",
        line_number=12,
        file_path="app.py",
        language="Python",
        callee_name="db.execute",
        arguments=["clean_id"],
    )
    callee_fn.body_statements = [san_assign, sink_call]

    cfg_main = CFGBuilder().build_cfg(caller_fn)
    cfg_helper = CFGBuilder().build_cfg(callee_fn)

    ssa_main = SSABuilder().build_ssa(cfg_main)
    ssa_helper = SSABuilder().build_ssa(cfg_helper)

    dfg_main = DataFlowBuilder().build_dataflow_graph(cfg_main, ssa_main)
    dfg_helper = DataFlowBuilder().build_dataflow_graph(cfg_helper, ssa_helper)

    intra_engine = IntraproceduralTaintEngine()
    tg_main = intra_engine.analyze_function(cfg_main, ssa_main, dfg_main)
    tg_helper = intra_engine.analyze_function(cfg_helper, ssa_helper, dfg_helper)

    inter_engine = InterproceduralTaintEngine()
    itg = inter_engine.analyze_program(
        taint_graphs={"safe_main": tg_main, "safe_query_db": tg_helper},
        dfg_map={"safe_main": dfg_main, "safe_query_db": dfg_helper},
    )

    assert len(itg.safe_paths) >= 1
    assert len(itg.vulnerable_paths) == 0


def test_summary_cache_and_pass_integration() -> None:
    cache = SummaryCache()
    assert cache.size == 0

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
    manager.register_pass(InterproceduralTaintPass())

    final_context = manager.run_passes(context)
    assert final_context.artifact_store.has("InterproceduralTaintGraph")
    res = final_context.artifact_store.get("InterproceduralTaintGraph")
    assert "program" in res
