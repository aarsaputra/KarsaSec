from __future__ import annotations

import pytest

from karsasec.analysis.cfg.builder import CFGBuilder
from karsasec.analysis.cfg.cfg_pass import CFGPass
from karsasec.analysis.cfg.models import (
    CFG,
    CFGEdgeType,
    CFGNode,
    CFGNodeType,
    EntryNode,
    ExitNode,
)
from karsasec.analysis.cfg.validator import CFGValidationError, CFGValidator
from karsasec.core.pipeline.context import PassContext
from karsasec.core.pipeline.pass_manager import PassManager
from karsasec.ir.nodes import IRAssignment, IRCall, IRFunction, IRIf, IRLoop, IRReturn


def test_cfg_models_and_exporters() -> None:
    cfg = CFG(function_name="main", file_path="app.py")
    entry = EntryNode(cfg_id="app.py::main::1")
    exit_node = ExitNode(cfg_id="app.py::main::1")

    stmt = CFGNode(
        id="app.py::main::stmt::2",
        node_type=CFGNodeType.STATEMENT,
        line_number=2,
        label="x = 1",
    )

    cfg.add_node(entry)
    cfg.add_node(stmt)
    cfg.add_node(exit_node)

    cfg.add_edge(entry.id, stmt.id, CFGEdgeType.NORMAL)
    cfg.add_edge(stmt.id, exit_node.id, CFGEdgeType.NORMAL)

    assert cfg.entry_node_id == entry.id
    assert cfg.exit_node_id == exit_node.id
    assert len(cfg.nodes) == 3
    assert len(cfg.edges) == 2

    # Check exporters
    mermaid_str = cfg.to_mermaid()
    assert "flowchart TD" in mermaid_str
    assert "ENTRY" in mermaid_str

    dot_str = cfg.to_dot()
    assert 'digraph "main"' in dot_str
    assert "ENTRY" in dot_str

    json_str = cfg.to_json()
    assert '"function_name": "main"' in json_str


def test_cfg_builder_simple_function() -> None:
    ir_func = IRFunction(
        id="main.py::foo::1",
        line_number=1,
        file_path="main.py",
        language="Python",
        name="foo",
    )

    assign = IRAssignment(
        id="main.py::assign::2",
        line_number=2,
        file_path="main.py",
        language="Python",
        target="a",
        value_expression="10",
    )

    ret = IRReturn(
        id="main.py::ret::3",
        line_number=3,
        file_path="main.py",
        language="Python",
        value_expression="a",
    )

    ir_func.body_statements = [assign, ret]

    builder = CFGBuilder()
    cfg = builder.build_cfg(ir_func)

    validator = CFGValidator()
    assert validator.validate(cfg) is True


def test_cfg_builder_if_else_branches() -> None:
    ir_func = IRFunction(
        id="main.py::check::1",
        line_number=1,
        file_path="main.py",
        language="Python",
        name="check",
    )

    if_stmt = IRIf(
        id="main.py::if::2",
        line_number=2,
        file_path="main.py",
        language="Python",
        condition_expr="user_id > 0",
        then_statements=[
            IRAssignment(
                id="main.py::assign::3",
                line_number=3,
                file_path="main.py",
                language="Python",
                target="valid",
                value_expression="True",
            )
        ],
        else_statements=[
            IRAssignment(
                id="main.py::assign::5",
                line_number=5,
                file_path="main.py",
                language="Python",
                target="valid",
                value_expression="False",
            )
        ],
    )

    ir_func.body_statements = [if_stmt]

    builder = CFGBuilder()
    cfg = builder.build_cfg(ir_func)

    validator = CFGValidator()
    assert validator.validate(cfg) is True


def test_cfg_builder_loop() -> None:
    ir_func = IRFunction(
        id="main.py::loop_fn::1",
        line_number=1,
        file_path="main.py",
        language="Python",
        name="loop_fn",
    )

    loop_stmt = IRLoop(
        id="main.py::while::2",
        line_number=2,
        file_path="main.py",
        language="Python",
        loop_type="WHILE",
        condition_expr="i < 10",
        body_statements=[
            IRCall(
                id="main.py::call::3",
                line_number=3,
                file_path="main.py",
                language="Python",
                callee_name="print",
                arguments=["i"],
            )
        ],
    )

    ir_func.body_statements = [loop_stmt]

    builder = CFGBuilder()
    cfg = builder.build_cfg(ir_func)

    validator = CFGValidator()
    assert validator.validate(cfg) is True


def test_cfg_validator_failures() -> None:
    validator = CFGValidator()

    # Test missing exit node
    invalid_cfg = CFG(function_name="bad", file_path="bad.py")
    entry = EntryNode("bad::ENTRY")
    invalid_cfg.add_node(entry)
    with pytest.raises(CFGValidationError) as exc:
        validator.validate(invalid_cfg)
    assert "must have exactly 1 EXIT node" in str(exc.value)

    # Test orphan node
    exit_node = ExitNode("bad::EXIT")
    invalid_cfg.add_node(exit_node)
    invalid_cfg.add_edge(entry.id, exit_node.id, CFGEdgeType.NORMAL)

    orphan = CFGNode("bad::orphan", CFGNodeType.STATEMENT, 10, label="Orphan")
    invalid_cfg.add_node(orphan)

    with pytest.raises(CFGValidationError) as exc2:
        validator.validate(invalid_cfg)
    assert "orphan node" in str(exc2.value) or "unreachable nodes" in str(exc2.value)


def test_cfg_pass_integration() -> None:
    ir_func = IRFunction(
        id="app.py::run::1",
        line_number=1,
        file_path="app.py",
        language="Python",
        name="run",
    )

    context = PassContext()
    context.artifact_store.store("UniversalIR", [ir_func])

    manager = PassManager()
    manager.register_pass(CFGPass())

    final_context = manager.run_passes(context)
    assert final_context.artifact_store.has("CFG")
    cfgs = final_context.artifact_store.get("CFG")
    assert "run" in cfgs
