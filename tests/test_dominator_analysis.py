from __future__ import annotations

from karsasec.analysis.cfg.builder import CFGBuilder
from karsasec.analysis.cfg.dominator import DominatorAnalysis, SanitizerDominanceVerifier
from karsasec.ir.nodes import IRAssignment, IRCall, IRFunction


def test_dominator_analysis_linear_flow() -> None:
    ir_func = IRFunction(
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
        target="x",
        value_expression="1",
    )

    call = IRCall(
        id="app.py::call::3",
        line_number=3,
        file_path="app.py",
        language="Python",
        callee_name="print",
        arguments=["x"],
    )

    ir_func.body_statements = [assign, call]

    builder = CFGBuilder()
    cfg = builder.build_cfg(ir_func)

    dom = DominatorAnalysis(cfg)

    # ENTRY dominates all nodes
    assert dom.dominates(cfg.entry_node_id, cfg.exit_node_id) is True

    # EXIT post-dominates all nodes
    assert dom.post_dominates(cfg.exit_node_id, cfg.entry_node_id) is True


def test_sanitizer_dominance_verifier() -> None:
    ir_func = IRFunction(
        id="app.py::query::1",
        line_number=1,
        file_path="app.py",
        language="Python",
        name="query",
    )

    sanitizer_assign = IRAssignment(
        id="app.py::assign::2",
        line_number=2,
        file_path="app.py",
        language="Python",
        target="clean_id",
        value_expression="sanitize(raw_id)",
    )

    sink_call = IRCall(
        id="app.py::call::3",
        line_number=3,
        file_path="app.py",
        language="Python",
        callee_name="db.execute",
        arguments=["clean_id"],
    )

    ir_func.body_statements = [sanitizer_assign, sink_call]

    builder = CFGBuilder()
    cfg = builder.build_cfg(ir_func)

    dom = DominatorAnalysis(cfg)
    verifier = SanitizerDominanceVerifier(dom)

    # Find statement node containing sanitizer and sink
    stmt_node_id = [nid for nid, n in cfg.nodes.items() if n.node_type.value == "STATEMENT" and "Statement Block" in n.label][0]

    # Sanitizer block dominates sink execution -> SAFE
    assert verifier.is_sanitized(stmt_node_id, cfg.exit_node_id) is True
