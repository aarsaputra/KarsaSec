"""SummaryCache providing fast lookup and reuse of computed FunctionSummary objects."""

from __future__ import annotations

from karsasec.analysis.interprocedural.models import FunctionSummary


class SummaryCache:
    """Cache store holding compiled FunctionSummary objects to optimize interprocedural analysis."""

    def __init__(self) -> None:
        self._cache: dict[str, FunctionSummary] = {}

    def get(self, function_name: str) -> FunctionSummary | None:
        return self._cache.get(function_name)

    def has(self, function_name: str) -> bool:
        return function_name in self._cache

    def put(self, summary: FunctionSummary) -> None:
        self._cache[summary.function_name] = summary

    def clear(self) -> None:
        self._cache.clear()

    @property
    def size(self) -> int:
        return len(self._cache)
