"""Unit tests for SemanticResolver module across multiple languages."""

import tempfile
from pathlib import Path
from karsasec.parser.python_parser import python_parser_plugin
from karsasec.parser.generic_parser import js_parser, go_parser, php_parser
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
    code = """
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
