"""Unit tests for Tree-sitter Parser and PythonParserPlugin."""

from pathlib import Path
from karsasec.parser.python_parser import PythonParserPlugin
from karsasec.parser.tree_sitter import ts_engine

def test_ts_engine_python(tmp_path: Path) -> None:
    """Test TreeSitterEngine parsing Python code into a root FileNode."""
    code = b"import os\n\ndef hello():\n    pass\n"
    file_node = ts_engine.parse_code(code, "python", file_path=tmp_path / "test.py")
    assert file_node is not None
    assert file_node.node_type == "file"
    assert file_node.language == "python"
    assert file_node.node_id != ""
    assert file_node.total_lines == 4

def test_python_parser_plugin_parse_result(tmp_path: Path) -> None:
    """Test PythonParserPlugin extracting ParseResult and SymbolTable."""
    file_path = tmp_path / "sample.py"
    file_path.write_text("import sys\n\nclass MyClass:\n    pass\n\ndef calculate():\n    return 42\n", encoding="utf-8")

    plugin = PythonParserPlugin()
    assert plugin.can_parse(".py") is True
    assert plugin.supported_language == "Python"

    result = plugin.parse_file(file_path)
    assert result.language == "Python"
    assert result.root is not None
    assert result.root.node_type == "file"
    assert result.parser_version == "0.1.0"
    assert result.engine == "Tree-sitter v0.25"

    assert "calculate" in result.symbol_table.functions
    assert "MyClass" in result.symbol_table.classes
    assert any("import sys" in imp for imp in result.symbol_table.imports)
