"""Unit tests for backward taint propagation scenarios T1-T6, T9, T11, T12 (E11)."""

from karsasec.graph.dataflow import DataFlowAnalyzer, TaintState


def test_t1_direct_assignment_propagation() -> None:
    code = """<?php
    $x = $_GET['x'];
    shell_exec($x);
    """
    analyzer = DataFlowAnalyzer()
    ev = analyzer.analyze_sink("shell_exec($x)", code, language="php")
    assert ev.state == TaintState.TAINTED
    assert ev.source_symbol == "$_GET"


def test_t2_two_hop_propagation() -> None:
    code = """<?php
    $x = $_GET['x'];
    $y = $x;
    shell_exec($y);
    """
    analyzer = DataFlowAnalyzer()
    ev = analyzer.analyze_sink("shell_exec($y)", code, language="php")
    assert ev.state == TaintState.TAINTED


def test_t3_three_hop_propagation() -> None:
    code = """<?php
    $x = $_GET['x'];
    $y = $x;
    $z = $y;
    shell_exec($z);
    """
    analyzer = DataFlowAnalyzer()
    ev = analyzer.analyze_sink("shell_exec($z)", code, language="php")
    assert ev.state == TaintState.TAINTED


def test_t4_constant_string_literal() -> None:
    code = """<?php
    $x = "constant";
    shell_exec($x);
    """
    analyzer = DataFlowAnalyzer()
    ev = analyzer.analyze_sink("shell_exec($x)", code, language="php")
    assert ev.state == TaintState.STATIC


def test_t5_static_constant_definition() -> None:
    code = """<?php
    define('BASE', '../');
    require_once BASE . 'foo.php';
    """
    analyzer = DataFlowAnalyzer()
    ev = analyzer.analyze_sink("require_once BASE . 'foo.php'", code, language="php")
    assert ev.state == TaintState.STATIC


def test_t6_tainted_constant_definition() -> None:
    code = """<?php
    define('BASE', $_GET['p']);
    require_once BASE . 'foo.php';
    """
    analyzer = DataFlowAnalyzer()
    ev = analyzer.analyze_sink("require_once BASE . 'foo.php'", code, language="php")
    assert ev.state == TaintState.TAINTED


def test_t9_concatenation_propagation() -> None:
    code = """<?php
    $x = $_GET['x'];
    $y = "ping " . $x;
    shell_exec($y);
    """
    analyzer = DataFlowAnalyzer()
    ev = analyzer.analyze_sink("shell_exec($y)", code, language="php")
    assert ev.state == TaintState.TAINTED


def test_t11_cycle_protection() -> None:
    code = """<?php
    $a = $b;
    $b = $a;
    shell_exec($a);
    """
    analyzer = DataFlowAnalyzer()
    ev = analyzer.analyze_sink("shell_exec($a)", code, language="php")
    assert ev.state == TaintState.UNKNOWN
    assert ev.truncated is True
