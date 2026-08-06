from pathlib import Path

from karsasec.ir.builder import IRBuilder
from karsasec.ir.nodes import IRAssignment, IRCall, IRFunction
from karsasec.parser.ast_nodes import (
    AssignmentNode,
    FileNode,
    FunctionNode,
    Position,
)
from karsasec.parser.ast_nodes import (
    CallNode as ASTCallNode,
)


def test_universal_ir_models() -> None:
    ir_func = IRFunction(
        id="app.py::main::1",
        line_number=1,
        file_path="app.py",
        language="Python",
        name="main",
        parameters=["req"],
    )

    assign = IRAssignment(
        id="app.py::assign::2",
        line_number=2,
        file_path="app.py",
        language="Python",
        target="query",
        value_expression="req.args.get('q')",
    )

    call = IRCall(
        id="app.py::call::3",
        line_number=3,
        file_path="app.py",
        language="Python",
        callee_name="db.execute",
        arguments=["query"],
    )

    ir_func.body_statements.append(assign)
    ir_func.body_statements.append(call)

    d = ir_func.to_dict()
    assert d["name"] == "main"
    assert len(d["body_statements"]) == 2
    assert d["body_statements"][0]["target"] == "query"
    assert d["body_statements"][1]["callee_name"] == "db.execute"


def test_universal_ir_builder() -> None:
    file_node = FileNode(
        node_id="root",
        file_path=Path("main.py"),
        language="Python",
        start=Position(1, 0),
        end=Position(20, 0),
    )

    fn = FunctionNode(
        node_id="fn_1",
        parent_id="root",
        language="Python",
        file_path=Path("main.py"),
        name="process_request",
        start=Position(1, 0),
        end=Position(10, 0),
        parameters=["req"],
    )

    assign = AssignmentNode(
        node_id="assign_1",
        parent_id="fn_1",
        language="Python",
        file_path=Path("main.py"),
        start=Position(3, 0),
        end=Position(3, 20),
        target="user_id",
        value_expression="req.get('id')",
    )

    call = ASTCallNode(
        node_id="call_1",
        parent_id="fn_1",
        language="Python",
        file_path=Path("main.py"),
        start=Position(5, 0),
        end=Position(5, 30),
        function_name="sql.execute",
        arguments=["user_id"],
    )

    file_node.nodes_map = {
        "root": file_node,
        "fn_1": fn,
        "assign_1": assign,
        "call_1": call,
    }

    builder = IRBuilder()
    ir_funcs = builder.build_from_file_nodes([file_node])

    assert len(ir_funcs) == 1
    assert ir_funcs[0].name == "process_request"
    assert len(ir_funcs[0].body_statements) == 2
    assert isinstance(ir_funcs[0].body_statements[0], IRAssignment)
    assert isinstance(ir_funcs[0].body_statements[1], IRCall)
