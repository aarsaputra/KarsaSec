"""SummaryCache providing fast lookup, invalidation, and recursion tracking for FunctionSummary objects."""

from __future__ import annotations

from karsasec.analysis.interprocedural.models import FunctionSummary, RecursionState


class SummaryCache:
    """Cache store holding compiled FunctionSummary objects with recursion state tracking."""

    def __init__(self) -> None:
        self._cache: dict[str, FunctionSummary] = {}
        self._states: dict[str, RecursionState] = {}

    def put(self, summary: FunctionSummary) -> None:
        self._cache[summary.function_name] = summary
        self._states[summary.function_name] = RecursionState.VISITED

    def get(self, function_name: str) -> FunctionSummary | None:
        return self._cache.get(function_name)

    def contains(self, function_name: str) -> bool:
        return function_name in self._cache

    def invalidate(self, function_name: str) -> None:
        self._cache.pop(function_name, None)
        self._states.pop(function_name, None)

    def get_state(self, function_name: str) -> RecursionState:
        return self._states.get(function_name, RecursionState.UNVISITED)

    def set_state(self, function_name: str, state: RecursionState) -> None:
        self._states[function_name] = state

    def clear(self) -> None:
        self._cache.clear()
        self._states.clear()

    @property
    def size(self) -> int:
        return len(self._cache)
