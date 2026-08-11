"""Unit tests for expanded interprocedural data-flow, parameter/return propagation, and sanitizer helper propagation (E12-5)."""

from karsasec.graph.dataflow.analyzer import DataFlowAnalyzer
from karsasec.graph.dataflow.model import TaintState
from karsasec.graph.dataflow.sinks import SinkCategory


def test_parameter_propagation_to_sink() -> None:
    source_code = """<?php
function execute($cmd) {
    system($cmd);
}

$input = $_GET['cmd'];
execute($input);
"""
    analyzer = DataFlowAnalyzer()
    evidence = analyzer.analyze_sink(
        snippet="system($cmd);",
        source_text=source_code,
        language="php",
        sink_category=SinkCategory.COMMAND_EXECUTION,
        line_number=3,
    )
    assert evidence.state == TaintState.TAINTED
    assert evidence.source_symbol == "$_GET"


def test_return_value_propagation_to_sink() -> None:
    source_code = """<?php
function getInput() {
    return $_GET['cmd'];
}

$x = getInput();
system($x);
"""
    analyzer = DataFlowAnalyzer()
    evidence = analyzer.analyze_sink(
        snippet="system($x);",
        source_text=source_code,
        language="php",
        sink_category=SinkCategory.COMMAND_EXECUTION,
        line_number=7,
    )
    assert evidence.state == TaintState.TAINTED
    assert evidence.source_symbol == "$_GET"


def test_sanitizer_helper_propagation() -> None:
    source_code = """<?php
function cleanInput($val) {
    return escapeshellarg($val);
}

$clean = cleanInput($_GET['cmd']);
system($clean);
"""
    analyzer = DataFlowAnalyzer()
    evidence = analyzer.analyze_sink(
        snippet="system($clean);",
        source_text=source_code,
        language="php",
        sink_category=SinkCategory.COMMAND_EXECUTION,
        line_number=7,
    )
    assert evidence.state == TaintState.SANITIZED


def test_incompatible_sanitizer_helper_remains_tainted() -> None:
    source_code = """<?php
function cleanHtml($val) {
    return htmlspecialchars($val);
}

$bad_clean = cleanHtml($_GET['cmd']);
system($bad_clean);
"""
    analyzer = DataFlowAnalyzer()
    evidence = analyzer.analyze_sink(
        snippet="system($bad_clean);",
        source_text=source_code,
        language="php",
        sink_category=SinkCategory.COMMAND_EXECUTION,
        line_number=7,
    )
    assert evidence.state == TaintState.TAINTED


def test_cycle_protection_in_recursive_assignments() -> None:
    source_code = """<?php
$a = $b;
$b = $a;
system($a);
"""
    analyzer = DataFlowAnalyzer()
    evidence = analyzer.analyze_sink(
        snippet="system($a);",
        source_text=source_code,
        language="php",
        sink_category=SinkCategory.COMMAND_EXECUTION,
        line_number=4,
    )
    assert evidence.state in (TaintState.STATIC, TaintState.UNKNOWN)
    assert evidence.truncated is True
