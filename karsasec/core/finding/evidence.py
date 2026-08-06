"""Immutable Evidence model capturing code snippet, line, column, and context lines."""

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Evidence:
    """Immutable evidence representation containing vulnerable code snippet and context lines."""
    snippet: str
    line: int
    column: int
    context_lines: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)
