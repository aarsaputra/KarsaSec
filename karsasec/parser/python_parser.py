"""Python ParserPlugin implementation utilizing Tree-sitter & AST SymbolTable extraction with native AST fallback."""

import ast
import time
from pathlib import Path

from karsasec.core.plugin import Diagnostic, ParseResult, ParserPlugin, SymbolTable
from karsasec.parser.ast_nodes import ASTNode, FileNode, Position, generate_node_id
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
        diagnostics: list[Diagnostic] = []

        functions: list[str] = []
        classes: list[str] = []
        imports: list[str] = []
        globals_list: list[str] = []

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
        file_node: FileNode | None = ts_engine.parse_code(code_bytes, "python", file_path=path)

        # Native Python AST symbol extraction and AST fallback if tree-sitter children are empty
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

            if file_node and not file_node.children:
                file_node = self._build_from_native_ast(py_ast, path, code_bytes)

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
            engine="Tree-sitter / Native Fallback",
        )

    def _build_from_native_ast(self, py_ast: ast.AST, path: Path, code_bytes: bytes) -> FileNode:
        """Converts native Python ast tree to KarsaSec FileNode and ASTNode structure."""
        nodes_map: dict[str, ASTNode] = {}

        # Build line offset table for byte calculation
        line_offsets = [0]
        offset = 0
        for line in code_bytes.splitlines(keepends=True):
            offset += len(line)
            line_offsets.append(offset)

        def get_byte_offset(line: int, col: int) -> int:
            if line < 1:
                return 0
            idx = line - 1
            if idx >= len(line_offsets):
                return len(code_bytes)
            line_start = line_offsets[idx]
            line_end = line_offsets[idx + 1] if idx + 1 < len(line_offsets) else len(code_bytes)
            return min(line_start + col, line_end)

        def _convert(py_node: ast.AST, parent_id: str | None) -> ASTNode:
            line_no = getattr(py_node, "lineno", 1)
            col_no = getattr(py_node, "col_offset", 0)
            end_line = getattr(py_node, "end_lineno", line_no)
            end_col = getattr(py_node, "end_col_offset", col_no)

            raw_type = py_node.__class__.__name__.lower()
            if isinstance(py_node, ast.Call):
                node_type = "call"
            elif isinstance(py_node, ast.Attribute):
                node_type = "attribute"
            elif isinstance(py_node, ast.Name):
                node_type = "name"
            elif isinstance(py_node, ast.Constant):
                node_type = "string" if isinstance(py_node.value, str) else "number"
            elif isinstance(py_node, ast.FunctionDef):
                node_type = "function_definition"
            elif isinstance(py_node, ast.ClassDef):
                node_type = "class_definition"
            else:
                node_type = raw_type

            node_id = generate_node_id(path, line_no, col_no, node_type)

            children_ids: list[str] = []
            for field_name, child in ast.iter_fields(py_node):
                if isinstance(child, ast.AST):
                    c_node = _convert(child, node_id)
                    children_ids.append(c_node.node_id)
                elif isinstance(child, list):
                    for item in child:
                        if isinstance(item, ast.AST):
                            c_node = _convert(item, node_id)
                            children_ids.append(c_node.node_id)

            ast_node = ASTNode(
                node_id=node_id,
                parent_id=parent_id,
                node_type=node_type,
                language="Python",
                file_path=path,
                byte_start=get_byte_offset(line_no, col_no),
                byte_end=get_byte_offset(end_line, end_col),
                start=Position(line=line_no, column=col_no),
                end=Position(line=end_line, column=end_col),
                children=children_ids,
            )
            nodes_map[node_id] = ast_node
            return ast_node

        root_ast_node = _convert(py_ast, None)

        total_lines = len(code_bytes.splitlines())
        file_node = FileNode(
            node_id=root_ast_node.node_id,
            parent_id=None,
            node_type="file",
            language="Python",
            file_path=path,
            byte_start=0,
            byte_end=len(code_bytes),
            start=Position(1, 0),
            end=Position(total_lines or 1, 0),
            children=root_ast_node.children,
            total_lines=total_lines,
            nodes_map=nodes_map,
        )

        return file_node


# Register default Python parser instance
python_parser_plugin = PythonParserPlugin()
parser_registry.register(python_parser_plugin, [".py", ".pyi"])
