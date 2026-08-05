"""GitHub Actions Workflow AST Parser Plugin producing standardized FileNode and ASTNode objects."""

import time
from pathlib import Path
from typing import Dict, List, Optional

from karsasec.core.plugin import ParseResult, ParserPlugin, SymbolTable
from karsasec.parser.ast_nodes import ASTNode, FileNode, Position, generate_node_id


class GitHubActionsParserPlugin(ParserPlugin):
    """AST parser plugin for GitHub Actions Workflows."""

    def __init__(self) -> None:
        self._extensions = [".yaml", ".yml"]

    @property
    def name(self) -> str:
        return "GitHubActionsParser"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def supported_language(self) -> str:
        return "GitHub-Actions"

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
        lines = code_bytes.decode("utf-8", errors="ignore").splitlines(keepends=True)

        nodes_map: Dict[str, ASTNode] = {}
        children_ids: List[str] = []

        line_offsets = [0]
        offset = 0
        for line in lines:
            offset += len(line.encode("utf-8", errors="ignore"))
            line_offsets.append(offset)

        for idx, line in enumerate(lines, start=1):
            clean = line.strip()
            if not clean or clean.startswith("#"):
                continue

            node_type = "statement"
            if clean.startswith("run:") or clean.startswith("uses:") or clean.startswith("on:"):
                node_type = "call"

            clean_line = line.rstrip("\r\n")
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
        file_node = FileNode(
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

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        return ParseResult(
            language=self.supported_language,
            file_path=path,
            root=file_node,
            symbol_table=SymbolTable(),
            parse_time_ms=round(elapsed_ms, 2),
            parser_version=self.version,
            engine="GitHub Actions Native Tokenizer",
        )


gha_parser_plugin = GitHubActionsParserPlugin()
