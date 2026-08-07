"""Python AST Adapter providing abstract AST traversal and node wrapping."""

from __future__ import annotations

import ast
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ASTNodeWrapper:
    """Wrapper around raw AST nodes providing unified node accessors."""
    raw_node: Any
    node_type: str
    file_path: str = ""
    line: int = 1
    column: int = 0
    end_line: int = 1
    end_column: int = 0
    text: str = ""
    children: list[ASTNodeWrapper] = field(default_factory=list)

    @classmethod
    def wrap(cls, raw: Any, file_path: str = "") -> ASTNodeWrapper:
        """Wraps standard ast.AST node into ASTNodeWrapper."""
        node_type = raw.__class__.__name__
        line = getattr(raw, "lineno", 1)
        column = getattr(raw, "col_offset", 0)
        end_line = getattr(raw, "end_lineno", line)
        end_column = getattr(raw, "end_col_offset", column)

        wrapper = cls(
            raw_node=raw,
            node_type=node_type,
            file_path=file_path,
            line=line,
            column=column,
            end_line=end_line,
            end_column=end_column,
        )
        return wrapper


class PythonASTAdapter:
    """Adapter parsing Python code strings or files into ASTNodeWrapper trees."""

    @staticmethod
    def parse_code(code_str: str, file_path: str = "") -> ASTNodeWrapper | None:
        """Parses Python source code string into ASTNodeWrapper tree."""
        try:
            tree = ast.parse(code_str, filename=file_path or "<unknown>")
            return PythonASTAdapter.from_ast(tree, file_path=file_path)
        except SyntaxError:
            return None

    @staticmethod
    def parse_file(file_path: str | Path) -> ASTNodeWrapper | None:
        """Reads and parses Python file into ASTNodeWrapper tree."""
        path = Path(file_path)
        if not path.exists():
            return None
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            return PythonASTAdapter.parse_code(content, file_path=str(path))
        except OSError:
            return None

    @staticmethod
    def from_ast(tree: ast.AST, file_path: str = "") -> ASTNodeWrapper:
        """Recursively wraps an ast.AST tree into ASTNodeWrapper nodes."""
        root = ASTNodeWrapper.wrap(tree, file_path=file_path)
        for child in ast.iter_child_nodes(tree):
            root.children.append(PythonASTAdapter.from_ast(child, file_path=file_path))
        return root

    @staticmethod
    def walk(root: ASTNodeWrapper, visitor_fn: Callable[[ASTNodeWrapper], None]) -> None:
        """Depth-first walk over ASTNodeWrapper tree calling visitor_fn on each wrapper."""
        visitor_fn(root)
        for child in root.children:
            PythonASTAdapter.walk(child, visitor_fn)
