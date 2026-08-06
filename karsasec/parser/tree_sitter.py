"""Stateless Tree-sitter AST Engine Wrapper for multi-language syntax parsing."""

import threading
from pathlib import Path
from typing import Any

from karsasec.parser.ast_nodes import ASTNode, FileNode, Position, generate_node_id

try:
    import tree_sitter  # noqa: F401
    from tree_sitter import Language, Parser
    HAS_TREE_SITTER = True
except ImportError:
    HAS_TREE_SITTER = False

class TreeSitterEngine:
    """Stateless wrapper over tree-sitter library for parsing source code into ASTNode trees."""

    def __init__(self) -> None:
        self._languages: dict[str, Any] = {}
        self._lock = threading.Lock()

    def get_language(self, language_name: str) -> Any | None:
        """Gets or initializes a cached tree-sitter Language instance in a thread-safe manner."""
        if not HAS_TREE_SITTER:
            return None

        lang_key = language_name.lower()

        with self._lock:
            if lang_key in self._languages:
                return self._languages[lang_key]

            try:
                lang_obj = None
                if lang_key == "python":
                    import tree_sitter_python as tspython
                    lang_obj = Language(tspython.language())
                elif lang_key in ("javascript", "typescript", "js", "ts"):
                    import tree_sitter_javascript as tsjs
                    lang_obj = Language(tsjs.language())
                elif lang_key == "php":
                    import tree_sitter_php as tsphp
                    lang_obj = Language(tsphp.language_php())
                elif lang_key == "go":
                    import tree_sitter_go as tsgo
                    lang_obj = Language(tsgo.language())
                elif lang_key == "rust":
                    import tree_sitter_rust as tsrust
                    lang_obj = Language(tsrust.language())
                elif lang_key == "java":
                    import tree_sitter_java as tsjava
                    lang_obj = Language(tsjava.language())

                if lang_obj:
                    self._languages[lang_key] = lang_obj
                    return lang_obj
            except Exception:
                pass

            return None

    def parse_code(self, code_bytes: bytes, language_name: str, file_path: Path | None = None) -> FileNode:
        """Parses raw source bytes into a root FileNode AST."""
        path = file_path or Path("memory.src")
        total_lines = len(code_bytes.splitlines())

        lang_obj = self.get_language(language_name)
        if not lang_obj:
            # Fallback root FileNode if tree-sitter grammar is not available
            root_id = generate_node_id(path, 0, len(code_bytes), "file")
            return FileNode(
                node_id=root_id,
                node_type="file",
                language=language_name,
                file_path=path,
                byte_start=0,
                byte_end=len(code_bytes),
                start=Position(1, 0),
                end=Position(total_lines or 1, 0),
                children=[],
                total_lines=total_lines,
            )

        parser = Parser(lang_obj)
        tree = parser.parse(code_bytes)

        node_lookup: dict[str, ASTNode] = {}
        root_ast_node = self._convert_ts_node(
            ts_node=tree.root_node,
            file_path=path,
            language_name=language_name,
            parent_id=None,
            node_lookup=node_lookup,
        )

        root_id = root_ast_node.node_id
        file_node = FileNode(
            node_id=root_id,
            parent_id=None,
            node_type="file",
            language=language_name,
            file_path=path,
            byte_start=root_ast_node.byte_start,
            byte_end=root_ast_node.byte_end,
            start=root_ast_node.start,
            end=root_ast_node.end,
            children=root_ast_node.children,
            total_lines=total_lines,
            nodes_map=node_lookup,
        )

        return file_node

    def parse_file(self, file_path: Path, language_name: str) -> FileNode | None:
        """Reads file and parses it into root FileNode."""
        try:
            code_bytes = file_path.read_bytes()
            return self.parse_code(code_bytes, language_name, file_path=file_path)
        except Exception:
            return None

    def _convert_ts_node(
        self,
        ts_node: Any,
        file_path: Path,
        language_name: str,
        parent_id: str | None,
        node_lookup: dict[str, ASTNode],
    ) -> ASTNode:
        """Recursively converts a tree-sitter Node to a KarsaSec ASTNode."""
        node_id = generate_node_id(file_path, ts_node.start_byte, ts_node.end_byte, ts_node.type)
        start_point = Position(line=ts_node.start_point[0] + 1, column=ts_node.start_point[1])
        end_point = Position(line=ts_node.end_point[0] + 1, column=ts_node.end_point[1])

        child_ids: list[str] = []
        for child in ts_node.children:
            child_node = self._convert_ts_node(
                ts_node=child,
                file_path=file_path,
                language_name=language_name,
                parent_id=node_id,
                node_lookup=node_lookup,
            )
            child_ids.append(child_node.node_id)

        ast_node = ASTNode(
            node_id=node_id,
            parent_id=parent_id,
            node_type=ts_node.type,
            language=language_name,
            file_path=file_path,
            byte_start=ts_node.start_byte,
            byte_end=ts_node.end_byte,
            start=start_point,
            end=end_point,
            children=child_ids,
        )

        node_lookup[node_id] = ast_node
        return ast_node

# Global default stateless engine instance
ts_engine = TreeSitterEngine()
