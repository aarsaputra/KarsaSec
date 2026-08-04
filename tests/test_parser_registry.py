"""Unit tests for ParserRegistry dual lookup."""

from pathlib import Path
from karsasec.parser.python_parser import PythonParserPlugin
from karsasec.parser.registry import ParserRegistry

def test_parser_registry_dual_lookup() -> None:
    registry = ParserRegistry()
    python_plugin = PythonParserPlugin()

    registry.register(python_plugin, [".py", ".pyi"])

    by_lang = registry.get_parser_by_language("Python")
    assert by_lang is python_plugin

    by_ext = registry.get_parser_by_extension(".py")
    assert by_ext is python_plugin

    by_file = registry.get_parser_for_file("app/main.py")
    assert by_file is python_plugin
