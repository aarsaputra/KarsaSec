"""Unit tests for ParserRegistry dual lookup."""

from pathlib import Path
from karsasec.parser.docker_parser import docker_parser_plugin
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


def test_parser_registry_dockerfile_lookup() -> None:
    registry = ParserRegistry()
    registry.register(docker_parser_plugin, ["dockerfile", ".dockerfile"])

    by_lang = registry.get_parser_by_language("Dockerfile")
    assert by_lang is docker_parser_plugin

    by_ext = registry.get_parser_by_extension(".dockerfile")
    assert by_ext is docker_parser_plugin

    by_file = registry.get_parser_for_file("Dockerfile")
    assert by_file is docker_parser_plugin
