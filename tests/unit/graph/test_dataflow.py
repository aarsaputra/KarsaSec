"""Unit tests for Data-Flow IR, DefUseExtractor, and GraphBuilder (E11)."""

from pathlib import Path

from karsasec.graph.dataflow import (
    DataFlowGraphBuilder,
    DefUseExtractor,
)


def test_def_use_extractor_direct_assignment() -> None:
    code = """<?php
    $x = $_GET['x'];
    $y = $x;
    """
    extractor = DefUseExtractor()
    assignments = extractor.extract_assignments(code, language="php")
    assert len(assignments) == 2

    assert assignments[0].variable_name == "$x"
    assert assignments[0].contains_source is True
    assert assignments[0].source_symbol == "$_GET"

    assert assignments[1].variable_name == "$y"
    assert "$x" in assignments[1].referenced_variables


def test_def_use_extractor_concatenation() -> None:
    code = """<?php
    $target = $_REQUEST['ip'];
    $cmd = 'ping -c 4 ' . $target;
    """
    extractor = DefUseExtractor()
    assignments = extractor.extract_assignments(code, language="php")
    assert len(assignments) == 2

    assert assignments[1].variable_name == "$cmd"
    assert assignments[1].is_concatenation is True
    assert "$target" in assignments[1].referenced_variables


def test_graph_builder_def_use_map() -> None:
    code = """<?php
    $a = $_GET['x'];
    $b = $a;
    $c = $b;
    """
    builder = DataFlowGraphBuilder()
    data = builder.build_graph(code, file_path=Path("test.php"), language="php")

    assert "$a" in data["def_use_map"]
    assert "$b" in data["def_use_map"]
    assert "$c" in data["def_use_map"]
    assert len(data["assignments"]) == 3
