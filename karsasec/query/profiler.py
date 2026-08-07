"""Query Profiler for timing and performance analysis across query stages."""

from __future__ import annotations

import time
from typing import Any


class QueryProfiler:
    """Profiler recording execution timings across Planning, Optimization, Traversal, and Predicate phases."""

    def __init__(self) -> None:
        self.stage_timings: dict[str, float] = {}
        self._stage_starts: dict[str, float] = {}

    def start_stage(self, stage_name: str) -> None:
        self._stage_starts[stage_name] = time.time()

    def stop_stage(self, stage_name: str) -> float:
        if stage_name in self._stage_starts:
            elapsed_ms = (time.time() - self._stage_starts[stage_name]) * 1000.0
            self.stage_timings[stage_name] = self.stage_timings.get(stage_name, 0.0) + elapsed_ms
            del self._stage_starts[stage_name]
            return elapsed_ms
        return 0.0

    def total_time_ms(self) -> float:
        return sum(self.stage_timings.values())

    def report(self) -> dict[str, Any]:
        return {
            "stage_timings_ms": self.stage_timings,
            "total_time_ms": self.total_time_ms(),
        }
