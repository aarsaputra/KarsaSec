"""Unit tests for Tree-sitter Parser and PythonParserPlugin."""

from pathlib import Path
from karsasec.parser.python_parser import PythonParserPlugin
from karsasec.parser.tree_sitter import ts_engine

def test_ts_engine_python(tmp_path: Path) -> None:
    """Test TreeSitterEngine parsing Python code."""
    code = b"import os\n\ndef hello():\n    pass\n"
    ast = ts_engine.parse_code(code, "python", file_path=tmp_path / "app.py")
    assert ast is not None
    assert ast.node_type == "file"

def test_python_parser_plugin(tmp_path: Path) -> None:
    """Test PythonParserPlugin extracting functions and imports."""
    file_path = tmp_path / "sample.py"
    file_path.write_text("import sys\n\nclass MyClass:\n    pass\n\ndef calculate():\n    return 42\n", encoding="utf-8")

    plugin = PythonParserPlugin()
    assert plugin.can_parse(".py") is True

    result = plugin.parse_file(file_path)
    assert result.language == "Python"
    assert "calculate" in result.symbol_table.functions
    assert "MyClass" in result.symbol_table.classes
    assert any("import sys" in imp for imp in result.symbol_table.imports)
