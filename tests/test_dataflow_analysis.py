from __future__ import annotations

from karsasec.analysis.cfg.builder import CFGBuilder
from karsasec.analysis.dataflow.builder import DataFlowBuilder
from karsasec.analysis.dataflow.dataflow_pass import DataFlowPass
from karsasec.analysis.dataflow.lattice import DataFlowLattice, LatticeElement
from karsasec.analysis.ssa.builder import SSABuilder
from karsasec.core.pipeline.context import PassContext
from karsasec.core.pipeline.pass_manager import PassManager
from karsasec.ir.nodes import IRAssignment, IRFunction


def test_lattice_meet_operations() -> None:
    top = LatticeElement.top()
    bot = LatticeElement.bottom()
    c5 = LatticeElement.constant(5)
    c10 = LatticeElement.constant(10)

    assert DataFlowLattice.meet(top, c5) == c5
    assert DataFlowLattice.meet(c5, bot) == bot
    assert DataFlowLattice.meet(c5, c5) == c5
    assert DataFlowLattice.meet(c5, c10) == bot


def test_dataflow_builder_constant_propagation_and_def_use() -> None:
    ir_func = IRFunction(
        id="app.py::calc::1",
        line_number=1,
        file_path="app.py",
        language="Python",
        name="calc",
    )

    a1 = IRAssignment(
        id="app.py::assign::2",
        line_number=2,
        file_path="app.py",
        language="Python",
        target="x",
        value_expression="42",
    )

    a2 = IRAssignment(
        id="app.py::assign::3",
        line_number=3,
        file_path="app.py",
        language="Python",
        target="y",
        value_expression="x",
    )

    ir_func.body_statements = [a1, a2]

    cfg = CFGBuilder().build_cfg(ir_func)
    ssa_func = SSABuilder().build_ssa(cfg)

    builder = DataFlowBuilder()
    dfg = builder.build_dataflow_graph(cfg, ssa_func)

    assert dfg.function_name == "calc"
    assert "x_1" in dfg.constant_values
    assert dfg.constant_values["x_1"] == 42
    assert len(dfg.def_use_chains) >= 1


def test_dataflow_pass_pipeline_integration() -> None:
    ir_func = IRFunction(
        id="app.py::run::1",
        line_number=1,
        file_path="app.py",
        language="Python",
        name="run",
    )

    cfg = CFGBuilder().build_cfg(ir_func)
    ssa_func = SSABuilder().build_ssa(cfg)

    context = PassContext()
    context.artifact_store.store("CFG", {"run": cfg})
    context.artifact_store.store("SSA", {"run": ssa_func})

    manager = PassManager()
    manager.register_pass(DataFlowPass())

    final_context = manager.run_passes(context)
    assert final_context.artifact_store.has("DataFlowGraph")
    dfg_map = final_context.artifact_store.get("DataFlowGraph")
    assert "run" in dfg_map
