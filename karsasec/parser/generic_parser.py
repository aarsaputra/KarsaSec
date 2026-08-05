"""Generic multi-language ParserPlugin utilizing Tree-sitter engine and pattern tokenization."""

import time
from pathlib import Path
from typing import Dict, List, Optional

from karsasec.core.plugin import ParseResult, ParserPlugin, SymbolTable
from karsasec.parser.ast_nodes import ASTNode, FileNode, Position, generate_node_id
from karsasec.parser.registry import parser_registry
from karsasec.parser.tree_sitter import ts_engine

class GenericParserPlugin(ParserPlugin):
    """Multi-language parser plugin supporting JavaScript, PHP, Go, and Common pattern parsing."""

    def __init__(self, language_name: str = "Generic", extensions: Optional[List[str]] = None) -> None:
        self._language = language_name
        self._extensions = extensions or [".js", ".ts", ".php", ".go", ".yaml", ".yml", ".json"]

    @property
    def name(self) -> str:
        return f"{self._language}Parser"

    @property
    def version(self) -> str:
        return "0.1.0"

    @property
    def supported_language(self) -> str:
        return self._language

    def can_parse(self, file_extension: str) -> bool:
        ext = file_extension.lower()
        if not ext.startswith("."):
            ext = f".{ext}"
        return ext in self._extensions

    def parse_file(self, file_path: Path) -> ParseResult:
        start_time = time.perf_counter()
        path = file_path.resolve()

        if not path.exists():
            return ParseResult(
                language=self.supported_language,
                file_path=path,
                root=None,
                symbol_table=SymbolTable(),
                parse_time_ms=(time.perf_counter() - start_time) * 1000,
            )

        code_bytes = path.read_bytes()
        file_node: Optional[FileNode] = ts_engine.parse_code(code_bytes, self.supported_language, file_path=path)

        if file_node and not file_node.children:
            file_node = self._build_pattern_ast(path, code_bytes)

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        return ParseResult(
            language=self.supported_language,
            file_path=path,
            root=file_node,
            symbol_table=SymbolTable(),
            parse_time_ms=round(elapsed_ms, 2),
            parser_version=self.version,
            engine="Tree-sitter / Generic Tokenizer",
        )

    def _build_pattern_ast(self, path: Path, code_bytes: bytes) -> FileNode:
        """Fallback AST node builder extracting call, assignment, and string nodes from source text."""
        nodes_map: Dict[str, ASTNode] = {}
        lines = code_bytes.decode("utf-8", errors="ignore").splitlines(keepends=True)
        children_ids: List[str] = []

        # Build line offset table for byte calculation
        line_offsets = [0]
        offset = 0
        for line in lines:
            offset += len(line.encode("utf-8", errors="ignore"))
            line_offsets.append(offset)

        in_block_comment = False

        def strip_comments_from_line(line: str, in_block: bool) -> tuple[str, bool]:
            if in_block:
                end_idx = line.find("*/")
                if end_idx == -1:
                    return "", True
                line = line[end_idx + 2 :]
                in_block = False

            while True:
                start_idx = line.find("/*")
                if start_idx == -1:
                    break
                end_idx = line.find("*/", start_idx + 2)
                if end_idx == -1:
                    line = line[:start_idx]
                    in_block = True
                    break
                line = line[:start_idx] + line[end_idx + 2 :]

            for token in ("//", "#"):
                idx = line.find(token)
                if idx != -1:
                    line = line[:idx]

            return line, in_block

        for idx, line in enumerate(lines, start=1):
            line_code, in_block_comment = strip_comments_from_line(line, in_block_comment)
            stripped = line_code.strip()
            if not stripped:
                continue

            node_type = "statement"
            if "(" in stripped and ")" in stripped:
                node_type = "call"
            elif "=" in stripped:
                node_type = "assignment"

            clean_line = line_code.rstrip("\r\n")
            line_start = line_offsets[idx - 1]

            node_id = generate_node_id(path, idx, 0, node_type)
            ast_node = ASTNode(
                node_id=node_id,
                parent_id=None,
                node_type=node_type,
                language=self.supported_language,
                file_path=path,
                byte_start=line_start,
                byte_end=line_start + len(clean_line.encode("utf-8", errors="ignore")),
                start=Position(line=idx, column=0),
                end=Position(line=idx, column=len(clean_line)),
            )
            nodes_map[node_id] = ast_node
            children_ids.append(node_id)

        total_lines = len(lines)
        root_id = generate_node_id(path, 0, len(code_bytes), "file")
        return FileNode(
            node_id=root_id,
            parent_id=None,
            node_type="file",
            language=self.supported_language,
            file_path=path,
            byte_start=0,
            byte_end=len(code_bytes),
            start=Position(1, 0),
            end=Position(total_lines or 1, 0),
            children=children_ids,
            total_lines=total_lines,
            nodes_map=nodes_map,
        )

# Register generic parser instances for JS, PHP, Go, Rust, Java, and common file formats
js_parser = GenericParserPlugin("JavaScript", [".js", ".jsx", ".ts", ".tsx"])
php_parser = GenericParserPlugin("PHP", [".php", ".phtml"])
go_parser = GenericParserPlugin("Go", [".go"])
rust_parser = GenericParserPlugin("Rust", [".rs"])
java_parser = GenericParserPlugin("Java", [".java"])
common_parser = GenericParserPlugin("Common", [".txt", ".env", ".yaml", ".yml", ".json"])

parser_registry.register(js_parser, [".js", ".jsx", ".ts", ".tsx"])
parser_registry.register(php_parser, [".php", ".phtml"])
parser_registry.register(go_parser, [".go"])
parser_registry.register(rust_parser, [".rs"])
parser_registry.register(java_parser, [".java"])
parser_registry.register(common_parser, [".txt", ".env", ".yaml", ".yml", ".json"])
