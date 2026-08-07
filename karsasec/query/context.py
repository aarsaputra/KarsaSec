"""Execution Context for stateless runtime execution of CPG Queries."""

from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass
class ExecutionMetrics:
    """Runtime metrics collected during query execution."""

    planning_time_ms: float = 0.0
    optimization_time_ms: float = 0.0
    execution_time_ms: float = 0.0
    nodes_scanned: int = 0
    edges_traversed: int = 0
    cache_hits: int = 0
    cache_misses: int = 0


class ExecutionContext:
    """Stateless runtime context carrying timeout, depth bounds, metrics, and cancellation token."""

    def __init__(
        self,
        timeout_seconds: float = 30.0,
        max_traversal_depth: int = 15,
        enable_cache: bool = True,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.max_traversal_depth = max_traversal_depth
        self.enable_cache = enable_cache
        self.start_time = time.time()
        self.metrics = ExecutionMetrics()
        self.is_cancelled = False

    def check_timeout(self) -> None:
        if self.is_cancelled:
            raise RuntimeError("Query execution cancelled by token.")
        if time.time() - self.start_time > self.timeout_seconds:
            raise TimeoutError(f"Query execution exceeded timeout limit of {self.timeout_seconds}s.")

    def cancel(self) -> None:
        self.is_cancelled = True
