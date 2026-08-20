"""Unit tests for ConstantEvaluator and Pre-Dataflow Constant Propagation Engine (E12-12)."""

import pytest
from karsasec.graph.dataflow.constant_evaluator import (
    ConstantEvaluator,
    LatticeKind,
)


@pytest.fixture
def evaluator() -> ConstantEvaluator:
    return ConstantEvaluator()


class TestConstantEvaluatorCategories:
    """15 required unit test categories for E12-12 Constant Propagation."""

    # 1. Literal constant
    def test_01_literal_constant(self, evaluator: ConstantEvaluator) -> None:
        val = evaluator.evaluate_expression('"SELECT * FROM users"')
        assert val.kind == LatticeKind.CONSTANT
        assert val.literal_value == "SELECT * FROM users"
        assert val.is_constant()

    # 2. Constant concatenation
    def test_02_constant_concatenation(self, evaluator: ConstantEvaluator) -> None:
        val = evaluator.evaluate_expression('"foo" . "bar"')
        assert val.kind == LatticeKind.CONSTANT
        assert val.literal_value == "foobar"

    # 3. Constant variable
    def test_03_constant_variable(self, evaluator: ConstantEvaluator) -> None:
        src = '$x = "a"; $y = $x;'
        env = evaluator.build_scope_environment(src)
        assert env["$x"].kind == LatticeKind.CONSTANT
        assert env["$x"].literal_value == "a"
        assert env["$y"].kind == LatticeKind.CONSTANT
        assert env["$y"].literal_value == "a"

    # 4. Constant chain
    def test_04_constant_chain(self, evaluator: ConstantEvaluator) -> None:
        src = '$a = "1"; $b = $a; $c = $b . "2";'
        env = evaluator.build_scope_environment(src)
        assert env["$c"].kind == LatticeKind.CONSTANT
        assert env["$c"].literal_value == "12"

    # 5. Dynamic variable
    def test_05_dynamic_variable(self, evaluator: ConstantEvaluator) -> None:
        src = '$x = $_GET["id"];'
        env = evaluator.build_scope_environment(src)
        assert env["$x"].kind == LatticeKind.DYNAMIC
        assert env["$x"].is_dynamic()

    # 6. Mixed constant + dynamic
    def test_06_mixed_constant_dynamic(self, evaluator: ConstantEvaluator) -> None:
        src = '$x = "SELECT * FROM users WHERE id=" . $_GET["id"];'
        env = evaluator.build_scope_environment(src)
        assert env["$x"].kind == LatticeKind.DYNAMIC

    # 7. GET/POST source
    def test_07_get_post_source(self, evaluator: ConstantEvaluator) -> None:
        val = evaluator.evaluate_expression('$_POST["name"]')
        assert val.kind == LatticeKind.DYNAMIC

    # 8. Constant function argument
    def test_08_constant_function_argument(self, evaluator: ConstantEvaluator) -> None:
        val = evaluator.evaluate_expression('strlen("static")')
        assert val.kind == LatticeKind.CONSTANT
        assert "strlen(static)" in val.literal_value

    # 9. Unknown function result
    def test_09_unknown_function_result(self, evaluator: ConstantEvaluator) -> None:
        val = evaluator.evaluate_expression("some_custom_func()")
        assert val.kind == LatticeKind.UNKNOWN
        assert val.is_unknown()
        assert not val.is_constant()

    # 10. Branch assignment
    def test_10_branch_assignment(self, evaluator: ConstantEvaluator) -> None:
        src = """
        if ($cond) {
            $x = "a";
        } else {
            $x = "b";
        }
        """
        env = evaluator.build_scope_environment(src)
        assert env["$x"].kind == LatticeKind.UNKNOWN

    # 11. Loop assignment
    def test_11_loop_assignment(self, evaluator: ConstantEvaluator) -> None:
        src = """
        while ($cond) {
            $x = "a";
            $x = "b";
        }
        """
        env = evaluator.build_scope_environment(src)
        assert env["$x"].kind == LatticeKind.UNKNOWN

    # 12. Variable reassignment
    def test_12_variable_reassignment(self, evaluator: ConstantEvaluator) -> None:
        src = """
        $x = "a";
        $x = $_GET["b"];
        """
        env = evaluator.build_scope_environment(src)
        assert env["$x"].kind == LatticeKind.UNKNOWN or env["$x"].kind == LatticeKind.DYNAMIC

    # 13. Scope isolation
    def test_13_scope_isolation(self, evaluator: ConstantEvaluator) -> None:
        src_foo = 'function foo() { $x = "a"; }'
        src_bar = "function bar() { echo $x; }"
        env_foo = evaluator.build_scope_environment(src_foo)
        env_bar = evaluator.build_scope_environment(src_bar)
        assert "$x" in env_foo
        assert "$x" not in env_bar

    # 14. SQL static query
    def test_14_sql_static_query(self, evaluator: ConstantEvaluator) -> None:
        val = evaluator.evaluate_expression('"SHOW COLUMNS FROM users"')
        assert val.kind == LatticeKind.CONSTANT
        assert val.literal_value == "SHOW COLUMNS FROM users"

    # 15. SQL dynamic query
    def test_15_sql_dynamic_query(self, evaluator: ConstantEvaluator) -> None:
        src = '$query = "SELECT * FROM users WHERE id=" . $_GET["id"];'
        env = evaluator.build_scope_environment(src)
        assert env["$query"].kind == LatticeKind.DYNAMIC
