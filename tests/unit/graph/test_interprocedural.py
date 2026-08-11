"""Unit tests for bounded inter-procedural parameter propagation T10 (E11)."""

from karsasec.graph.dataflow import DataFlowAnalyzer, TaintState


def test_t10_bounded_interprocedural_function_propagation() -> None:
    code = """<?php
    function run($x) {
        shell_exec($x);
    }

    run($_GET['cmd']);
    """
    analyzer = DataFlowAnalyzer()
    ev = analyzer.analyze_sink("shell_exec($x)", code, language="php")
    assert ev.state == TaintState.TAINTED
    assert ev.source_symbol == "$_GET"
