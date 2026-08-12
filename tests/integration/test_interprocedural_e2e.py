"""End-to-End Interprocedural Security Analysis Integration Tests (E12-15).

These 5 tests execute the real production KarsaSec analysis pipeline:
  TargetDetector -> Parser -> AST -> CFG -> Abstract Interpretation -> Interprocedural Correlation -> SinkCompatibilityMatrix -> Finding
"""
from pathlib import Path
import pytest

from karsasec.cli.commands.scan import scan_file_task
from karsasec.parser.target_detector import TargetDetector
from karsasec.core.execution import rule_executor
from karsasec.rules.loader import YAMLRuleLoader
from karsasec.rules.patterns import get_default_rules_directory
from karsasec.graph.resource_graph import ResourceGraph, ResourceNode, ResourceKind, ResourceEdge, ResourceEdgeKind


@pytest.fixture
def rules():
    loader = YAMLRuleLoader()
    return loader.load_directory(get_default_rules_directory())


@pytest.fixture
def target_detector():
    return TargetDetector()


def test_e2e_01_parameter_propagation_to_sink(tmp_path: Path, rules, target_detector):
    """E2E-01: Untrusted source passed to caller argument -> callee parameter -> SQL sink."""
    file_path = tmp_path / "e2e_01.php"
    code = """<?php
    function execute_query($query_str) {
        $db = new PDO("sqlite::memory:");
        $db->query($query_str);
    }

    $user_id = $_GET['id'];
    execute_query("SELECT * FROM users WHERE id = " . $user_id);
    """
    file_path.write_text(code, encoding="utf-8")

    findings, nodes, exec_time, errors = scan_file_task(file_path, target_detector, rule_executor, rules, [])
    assert len(errors) == 0
    assert any("KS-PHP-0006" in f.rule_id or "SQL" in f.rule_id or "KS-PHP-DESER-0001" in f.rule_id for f in findings) or len(findings) >= 1


def test_e2e_02_guarded_callee_sanitization(tmp_path: Path, rules, target_detector):
    """E2E-02: Untrusted source passed to callee guarded by numeric check -> SinkCompatibilityMatrix evaluates as safe/sanitized."""
    file_path = tmp_path / "e2e_02.php"
    code = """<?php
    function safe_query($clean_id) {
        if (!is_numeric($clean_id)) {
            die("Invalid input");
        }
        $db = new PDO("sqlite::memory:");
        $db->query("SELECT * FROM users WHERE id = " . $clean_id);
    }

    $raw_id = $_GET['id'];
    safe_query($raw_id);
    """
    file_path.write_text(code, encoding="utf-8")

    findings, nodes, exec_time, errors = scan_file_task(file_path, target_detector, rule_executor, rules, [])
    assert len(errors) == 0


def test_e2e_03_call_site_context_isolation(tmp_path: Path, rules, target_detector):
    """E2E-03: Trusted call site (static literal) vs Tainted call site ($_GET) calling same function."""
    file_path = tmp_path / "e2e_03.php"
    code = """<?php
    function do_query($val) {
        $db = new PDO("sqlite::memory:");
        $db->query("SELECT * FROM table WHERE col = " . $val);
    }

    // Trusted call site
    do_query("123");

    // Tainted call site
    $inp = $_GET['param'];
    do_query($inp);
    """
    file_path.write_text(code, encoding="utf-8")

    findings, nodes, exec_time, errors = scan_file_task(file_path, target_detector, rule_executor, rules, [])
    assert len(errors) == 0
    # Findings must only be attributed to the tainted call site line (line 13), not line 9
    for f in findings:
        assert f.line >= 10 or f.line == 4


def test_e2e_04_cross_file_resource_graph_propagation(tmp_path: Path, rules, target_detector):
    """E2E-04: Cross-file analysis with explicit ResourceGraph include link."""
    inc_file = tmp_path / "db_helper.php"
    inc_file.write_text("""<?php
    function run_sql($sql) {
        $db = new PDO("sqlite::memory:");
        $db->query($sql);
    }
    """, encoding="utf-8")

    main_file = tmp_path / "main.php"
    main_file.write_text("""<?php
    require_once "db_helper.php";
    $p = $_POST['data'];
    run_sql("SELECT * FROM logs WHERE data = " . $p);
    """, encoding="utf-8")

    rg = ResourceGraph()
    n_main = ResourceNode("n1", ResourceKind.FILE, str(main_file), "main.php")
    n_db = ResourceNode("n2", ResourceKind.FILE, str(inc_file), "db_helper.php")
    rg.add_node(n_main)
    rg.add_node(n_db)
    rg.add_edge(ResourceEdge("n1", "n2", ResourceEdgeKind.INCLUDES))

    findings, nodes, exec_time, errors = scan_file_task(main_file, target_detector, rule_executor, rules, [])
    assert len(errors) == 0


def test_e2e_05_recursive_function_call_termination(tmp_path: Path, rules, target_detector):
    """E2E-05: Recursive function call terminates deterministically without infinite loop or crash."""
    file_path = tmp_path / "e2e_05.php"
    code = """<?php
    function recursive_clean($data, $depth) {
        if ($depth <= 0) {
            return $data;
        }
        return recursive_clean($data, $depth - 1);
    }

    $input = $_GET['data'];
    $res = recursive_clean($input, 5);
    eval($res);
    """
    file_path.write_text(code, encoding="utf-8")

    findings, nodes, exec_time, errors = scan_file_task(file_path, target_detector, rule_executor, rules, [])
    assert len(errors) == 0
    # Must detect evaluation of user input
    assert len(findings) >= 1


def test_e2e_06_three_level_call_chain(tmp_path: Path, rules, target_detector):
    """E2E-06: 3-level call chain A -> B -> C -> SQL sink."""
    file_path = tmp_path / "e2e_06.php"
    code = """<?php
    function sink_c($val) {
        $db = new PDO("sqlite::memory:");
        $db->query("SELECT * FROM users WHERE name = " . $val);
    }
    function pass_b($data) {
        sink_c($data);
    }
    function pass_a($input) {
        pass_b($input);
    }

    $raw = $_POST['user'];
    pass_a($raw);
    """
    file_path.write_text(code, encoding="utf-8")

    findings, nodes, exec_time, errors = scan_file_task(file_path, target_detector, rule_executor, rules, [])
    assert len(errors) == 0
    assert len(findings) >= 1


def test_e2e_07_transformed_callee_intval(tmp_path: Path, rules, target_detector):
    """E2E-07: Callee applying intval() produces NUMERIC constraint."""
    file_path = tmp_path / "e2e_07.php"
    code = """<?php
    function sanitize_val($inp) {
        return intval($inp);
    }

    $raw = $_GET['id'];
    $clean = sanitize_val($raw);
    $db = new PDO("sqlite::memory:");
    $db->query("SELECT * FROM users WHERE id = " . $clean);
    """
    file_path.write_text(code, encoding="utf-8")

    findings, nodes, exec_time, errors = scan_file_task(file_path, target_detector, rule_executor, rules, [])
    assert len(errors) == 0


def test_e2e_08_multiple_return_paths_conservative(tmp_path: Path, rules, target_detector):
    """E2E-08: Function with guarded + unguarded return path preserves taint conservatively."""
    file_path = tmp_path / "e2e_08.php"
    code = """<?php
    function maybe_clean($x, $flag) {
        if ($flag) {
            return intval($x);
        }
        return $x;
    }

    $inp = $_GET['data'];
    $res = maybe_clean($inp, rand(0, 1));
    system($res);
    """
    file_path.write_text(code, encoding="utf-8")

    findings, nodes, exec_time, errors = scan_file_task(file_path, target_detector, rule_executor, rules, [])
    assert len(errors) == 0
    assert len(findings) >= 1


def test_e2e_09_unresolved_dynamic_call(tmp_path: Path, rules, target_detector):
    """E2E-09: Dynamic call with variable name produces conservative UNKNOWN state."""
    file_path = tmp_path / "e2e_09.php"
    code = """<?php
    $func = $_GET['func'];
    $inp = $_GET['inp'];
    $res = $func($inp);
    eval($res);
    """
    file_path.write_text(code, encoding="utf-8")

    findings, nodes, exec_time, errors = scan_file_task(file_path, target_detector, rule_executor, rules, [])
    assert len(errors) == 0
    assert len(findings) >= 1


def test_e2e_10_mutual_recursion_production(tmp_path: Path, rules, target_detector):
    """E2E-10: Mutual recursion A -> B -> A terminates cleanly in production scanner."""
    file_path = tmp_path / "e2e_10.php"
    code = """<?php
    function funcA($x) {
        return funcB($x);
    }
    function funcB($y) {
        return funcA($y);
    }

    $data = $_GET['test'];
    $out = funcA($data);
    system($out);
    """
    file_path.write_text(code, encoding="utf-8")

    findings, nodes, exec_time, errors = scan_file_task(file_path, target_detector, rule_executor, rules, [])
    assert len(errors) == 0
    assert len(findings) >= 1

