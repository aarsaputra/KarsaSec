"""Unit tests for SemanticResolver module across multiple languages."""

import tempfile
from pathlib import Path

from karsasec.parser.generic_parser import go_parser, js_parser, php_parser
from karsasec.parser.python_parser import python_parser_plugin
from karsasec.semantic.resolver import SemanticResolver


def test_python_semantic_resolution():
    code = """
import os
runner = os.system

def my_func():
    alias_run = runner
    alias_run("whoami")
"""
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(code)
        f_path = Path(f.name)

    try:
        parse_result = python_parser_plugin.parse_file(f_path)
        assert parse_result.root is not None

        resolver = SemanticResolver()
        graph = resolver.resolve_file(parse_result.root)

        # Let's locate the call node or alias_run node
        call_nodes = [node for node in parse_result.root.nodes_map.values() if node.node_type == "call"]
        assert len(call_nodes) >= 1

        # Verify alias_run("whoami") or similar call resolves to os.system
        resolved_symbols = list(graph.node_symbols.values())
        assert "os.system" in resolved_symbols

    finally:
        if f_path.exists():
            f_path.unlink()

def test_js_semantic_resolution():
    code = """
const os = require('child_process');
const exec = os.exec;
exec("whoami");
"""
    with tempfile.NamedTemporaryFile(suffix=".js", mode="w", delete=False) as f:
        f.write(code)
        f_path = Path(f.name)

    try:
        parse_result = js_parser.parse_file(f_path)
        assert parse_result.root is not None

        resolver = SemanticResolver()
        graph = resolver.resolve_file(parse_result.root)

        # Verify that exec("whoami") resolves to child_process.exec
        resolved_symbols = list(graph.node_symbols.values())
        assert "child_process.exec" in resolved_symbols

    finally:
        if f_path.exists():
            f_path.unlink()

def test_go_semantic_resolution():
    code = """
package main
import "os/exec"
func main() {
    runner := exec.Command
    runner("ls")
}
"""
    with tempfile.NamedTemporaryFile(suffix=".go", mode="w", delete=False) as f:
        f.write(code)
        f_path = Path(f.name)

    try:
        parse_result = go_parser.parse_file(f_path)
        assert parse_result.root is not None

        resolver = SemanticResolver()
        graph = resolver.resolve_file(parse_result.root)

        # Verify that runner("ls") resolves to os/exec.Command
        resolved_symbols = list(graph.node_symbols.values())
        assert "os/exec.Command" in resolved_symbols

    finally:
        if f_path.exists():
            f_path.unlink()

def test_php_semantic_resolution():
    code = r"""
<?php
use System\Process as Runner;
$proc = Runner;
$proc("ls");
?>
"""
    with tempfile.NamedTemporaryFile(suffix=".php", mode="w", delete=False) as f:
        f.write(code)
        f_path = Path(f.name)

    try:
        parse_result = php_parser.parse_file(f_path)
        assert parse_result.root is not None

        resolver = SemanticResolver()
        graph = resolver.resolve_file(parse_result.root)

        # Verify that $proc("ls") resolves to System.Process
        resolved_symbols = list(graph.node_symbols.values())
        assert "System.Process" in resolved_symbols

    finally:
        if f_path.exists():
            f_path.unlink()

def test_python_multi_import_resolution():
    code = """
import os, sys as system_module
runner = system_module.exit
runner(1)
"""
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(code)
        f_path = Path(f.name)

    try:
        parse_result = python_parser_plugin.parse_file(f_path)
        assert parse_result.root is not None
        resolver = SemanticResolver()
        graph = resolver.resolve_file(parse_result.root)
        resolved_symbols = list(graph.node_symbols.values())
        assert "sys.exit" in resolved_symbols
    finally:
        if f_path.exists():
            f_path.unlink()

def test_python_parenthesized_import_resolution():
    code = """
from subprocess import (
    call as run_cmd,
)
run_cmd('ls')
"""
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(code)
        f_path = Path(f.name)

    try:
        parse_result = python_parser_plugin.parse_file(f_path)
        assert parse_result.root is not None
        resolver = SemanticResolver()
        graph = resolver.resolve_file(parse_result.root)
        resolved_symbols = list(graph.node_symbols.values())
        assert "subprocess.call" in resolved_symbols
    finally:
        if f_path.exists():
            f_path.unlink()

def test_js_curly_brace_import_resolution():
    code = """
import { exec as run, spawn } from 'child_process';
run("whoami");
"""
    with tempfile.NamedTemporaryFile(suffix=".js", mode="w", delete=False) as f:
        f.write(code)
        f_path = Path(f.name)

    try:
        parse_result = js_parser.parse_file(f_path)
        assert parse_result.root is not None
        resolver = SemanticResolver()
        graph = resolver.resolve_file(parse_result.root)
        resolved_symbols = list(graph.node_symbols.values())
        assert "child_process.exec" in resolved_symbols
    finally:
        if f_path.exists():
            f_path.unlink()

def test_get_node_text_fallback_with_zero_offsets():
    from karsasec.parser.ast_nodes import ASTNode, Position
    from karsasec.semantic.resolver import get_node_text

    node = ASTNode(
        node_id="test",
        node_type="statement",
        byte_start=0,
        byte_end=0,
        start=Position(line=2, column=5),
        end=Position(line=2, column=15)
    )
    source = b"hello\nworldtargetcode\nfoo"
    text = get_node_text(node, source)
    assert text == "targetcode"
