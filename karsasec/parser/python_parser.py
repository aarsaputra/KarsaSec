"""Python ParserPlugin implementation utilizing Tree-sitter & AST SymbolTable extraction."""

import ast
import time
from pathlib import Path
from typing import List, Optional
from karsasec.core.plugin import Diagnostic, ParseResult, ParserPlugin, SymbolTable
from karsasec.parser.ast_nodes import FileNode
from karsasec.parser.registry import parser_registry
from karsasec.parser.tree_sitter import ts_engine

class PythonParserPlugin(ParserPlugin):
    """Python-specific parser plugin implementing AST analysis and SymbolTable generation."""

    @property
    def name(self) -> str:
        return "PythonParser"

    @property
    def version(self) -> str:
        return "0.1.0"

    @property
    def supported_language(self) -> str:
        return "Python"

    def can_parse(self, file_extension: str) -> bool:
        ext = file_extension.lower()
        if not ext.startswith("."):
            ext = f".{ext}"
        return ext in (".py", ".pyi")

    def parse_file(self, file_path: Path) -> ParseResult:
        """Parses a Python file and returns structured ParseResult."""
        start_time = time.perf_counter()
        path = file_path.resolve()
        diagnostics: List[Diagnostic] = []

        functions: List[str] = []
        classes: List[str] = []
        imports: List[str] = []
        globals_list: List[str] = []

        if not path.exists():
            diagnostics.append(
                Diagnostic(
                    code="PY001",
                    severity="ERROR",
                    message=f"File not found: {path}",
                    file_path=path,
                )
            )
            return ParseResult(
                language=self.supported_language,
                file_path=path,
                root=None,
                symbol_table=SymbolTable(),
                diagnostics=diagnostics,
                parse_time_ms=(time.perf_counter() - start_time) * 1000,
            )

        code_bytes = path.read_bytes()
        file_node: Optional[FileNode] = ts_engine.parse_code(code_bytes, "python", file_path=path)

        # Native Python AST symbol extraction for complete SymbolTable metadata
        try:
            content = code_bytes.decode("utf-8", errors="ignore")
            py_ast = ast.parse(content, filename=str(path))
            for node in py_ast.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    functions.append(node.name)
                elif isinstance(node, ast.ClassDef):
                    classes.append(node.name)
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(f"import {alias.name}")
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    for alias in node.names:
                        imports.append(f"from {module} import {alias.name}")
                elif isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            globals_list.append(target.id)
        except SyntaxError as se:
            diagnostics.append(
                Diagnostic(
                    code="PY002",
                    severity="WARNING",
                    message=f"Syntax warning/error during native AST parsing: {se.msg}",
                    file_path=path,
                    line=se.lineno or 0,
                    column=se.offset or 0,
                )
            )
        except Exception as ex:
            diagnostics.append(
                Diagnostic(
                    code="PY003",
                    severity="WARNING",
                    message=f"Error extracting symbols: {str(ex)}",
                    file_path=path,
                )
            )

        symbol_table = SymbolTable(
            functions=sorted(list(set(functions))),
            classes=sorted(list(set(classes))),
            imports=sorted(list(set(imports))),
            globals=sorted(list(set(globals_list))),
        )

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        return ParseResult(
            language=self.supported_language,
            file_path=path,
            root=file_node,
            symbol_table=symbol_table,
            diagnostics=diagnostics,
            parse_time_ms=round(elapsed_ms, 2),
            parser_version=self.version,
            engine="Tree-sitter v0.25",
        )

# Register default Python parser instance
python_parser_plugin = PythonParserPlugin()
parser_registry.register(python_parser_plugin, [".py", ".pyi"])
