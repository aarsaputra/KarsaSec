"""Persistent Symbol Store indexing function, class, and method definitions across project scope."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


@dataclass(frozen=True)
class SymbolEntry:
    """Indexed symbol entry storing qualified names, visibility, and source location."""
    name: str
    qualified_name: str
    kind: str  # function, class, method, variable, import
    file_path: Path
    line: int
    namespace: str = ""
    visibility: str = "public"


class SymbolStore:
    """In-memory and persistent index storing symbols across scanned workspaces."""

    def __init__(self) -> None:
        self._index: Dict[str, SymbolEntry] = {}
        self._by_file: Dict[Path, List[SymbolEntry]] = {}

    def register(self, entry: SymbolEntry) -> None:
        self._index[entry.qualified_name] = entry
        if entry.file_path not in self._by_file:
            self._by_file[entry.file_path] = []
        self._by_file[entry.file_path].append(entry)

    def lookup(self, qualified_name: str) -> Optional[SymbolEntry]:
        return self._index.get(qualified_name)

    def get_file_symbols(self, file_path: Path) -> List[SymbolEntry]:
        return self._by_file.get(file_path, [])

    def clear(self) -> None:
        self._index.clear()
        self._by_file.clear()


symbol_store = SymbolStore()
