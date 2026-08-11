"""Unit tests for sink-aware sanitizer evaluation T7, T8 (E11)."""

from karsasec.graph.dataflow import DataFlowAnalyzer, TaintState
from karsasec.graph.dataflow.sanitizers import SanitizerCapability, sanitizer_registry
from karsasec.graph.dataflow.sinks import SinkCategory


def test_t7_compatible_sanitizer_html_output() -> None:
    code = """<?php
    $x = $_GET['x'];
    $x = htmlspecialchars($x);
    echo $x;
    """
    analyzer = DataFlowAnalyzer()
    ev = analyzer.analyze_sink("echo $x", code, language="php", sink_category=SinkCategory.HTML_OUTPUT)
    assert ev.state == TaintState.SANITIZED


def test_t8_incompatible_sanitizer_shell_exec() -> None:
    code = """<?php
    $x = $_GET['x'];
    $x = htmlspecialchars($x);
    shell_exec($x);
    """
    analyzer = DataFlowAnalyzer()
    ev = analyzer.analyze_sink("shell_exec($x)", code, language="php", sink_category=SinkCategory.COMMAND_EXECUTION)
    assert ev.state == TaintState.TAINTED


def test_sanitizer_capability_compatibility() -> None:
    assert sanitizer_registry.is_compatible(SanitizerCapability.HTML_ESCAPE, SinkCategory.HTML_OUTPUT) is True
    assert sanitizer_registry.is_compatible(SanitizerCapability.HTML_ESCAPE, SinkCategory.COMMAND_EXECUTION) is False
    assert sanitizer_registry.is_compatible(SanitizerCapability.SHELL_ESCAPE, SinkCategory.COMMAND_EXECUTION) is True
    assert sanitizer_registry.is_compatible(SanitizerCapability.SQL_ESCAPE, SinkCategory.SQL_EXECUTION) is True
