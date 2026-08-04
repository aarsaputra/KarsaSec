"""Immutable Evidence model capturing code snippet, line, column, and context lines."""

from dataclasses import dataclass, field
from typing import Tuple

@dataclass(frozen=True)
class Evidence:
    """Immutable evidence representation containing vulnerable code snippet and context lines."""
    snippet: str
    line: int
    column: int
    context_lines: Tuple[str, ...] = field(default_factory=tuple)
