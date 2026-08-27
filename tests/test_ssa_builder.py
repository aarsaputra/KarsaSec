from __future__ import annotations

from karsasec.analysis.cfg.builder import CFGBuilder
from karsasec.analysis.ssa.builder import SSABuilder
from karsasec.analysis.ssa.models import SSAVar
from karsasec.analysis.ssa.ssa_pass import SSAPass
from karsasec.core.pipeline.context import PassContext
from karsasec.core.pipeline.pass_manager import PassManager
from karsasec.ir.nodes import IRAssignment, IRFunction


def test_ssa_var_and_models() -> None:
    v1 = SSAVar(base_name="a", version=1)
    assert v1.ssa_name == "a_1"


def test_ssa_builder_renaming() -> None:
    ir_func = IRFunction(
        id="app.py::foo::1",
        line_number=1,
        file_path="app.py",
        language="Python",
        name="foo",
    )

    a1 = IRAssignment(
        id="app.py::assign::2",
        line_number=2,
        file_path="app.py",
        language="Python",
        target="a",
        value_expression="1",
    )

    a2 = IRAssignment(
        id="app.py::assign::3",
        line_number=3,
        file_path="app.py",
        language="Python",
        target="a",
        value_expression="input()",
    )

    ir_func.body_statements = [a1, a2]

    cfg = CFGBuilder().build_cfg(ir_func)
    ssa_func = SSABuilder().build_ssa(cfg)

    assert len(ssa_func.nodes) == 2
    assert ssa_func.nodes[0].target.ssa_name == "a_1"
    assert ssa_func.nodes[1].target.ssa_name == "a_2"


def test_ssa_pass_pipeline_integration() -> None:
    ir_func = IRFunction(
        id="app.py::bar::1",
        line_number=1,
        file_path="app.py",
        language="Python",
        name="bar",
    )

    cfg = CFGBuilder().build_cfg(ir_func)

    context = PassContext()
    context.artifact_store.store("CFG", {"bar": cfg})

    manager = PassManager()
    manager.register_pass(SSAPass())

    final_context = manager.run_passes(context)
    assert final_context.artifact_store.has("SSA")
    ssa_map = final_context.artifact_store.get("SSA")
    assert "bar" in ssa_map


def test_ssa_builder_augmented_assignment() -> None:
    ir_func = IRFunction(
        id="app.py::foo::1",
        line_number=1,
        file_path="app.py",
        language="Python",
        name="foo",
    )

    a1 = IRAssignment(
        id="app.py::assign::2",
        line_number=2,
        file_path="app.py",
        language="Python",
        target="a",
        value_expression="1",
        operator="=",
    )

    a2 = IRAssignment(
        id="app.py::assign::3",
        line_number=3,
        file_path="app.py",
        language="Python",
        target="a",
        value_expression="2",
        operator=".=",
    )

    ir_func.body_statements = [a1, a2]

    cfg = CFGBuilder().build_cfg(ir_func)
    ssa_func = SSABuilder().build_ssa(cfg)

    assert len(ssa_func.nodes) == 2
    assert ssa_func.nodes[0].target.ssa_name == "a_1"
    assert ssa_func.nodes[1].target.ssa_name == "a_2"
    # The second statement should have "a_1" in its use_vars because of augmented assignment
    assert len(ssa_func.nodes[1].use_vars) == 1
    assert ssa_func.nodes[1].use_vars[0].ssa_name == "a_1"

