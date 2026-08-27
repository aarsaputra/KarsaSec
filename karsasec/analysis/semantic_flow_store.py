"""Authoritative, thread-safe SemanticFlowStore managing SemanticFlow instances for Sprint E11."""

from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from karsasec.analysis.semantic_flow import SemanticFlow

logger = logging.getLogger("karsasec.analysis.semantic_flow_store")


class SemanticFlowStore:
    """Thread-safe store for SemanticFlow objects with deterministic insertion & deduplication (INV-E11-FLOW-14)."""

    def __init__(self) -> None:
        self._flows: dict[str, SemanticFlow] = {}
        self._source_index: dict[str, list[SemanticFlow]] = {}
        self._sink_index: dict[str, list[SemanticFlow]] = {}
        self._lock = threading.RLock()

    def add(self, flow: SemanticFlow) -> bool:
        """Adds a SemanticFlow to the store.

        Returns True if newly inserted, False if duplicate (INV-E11-FLOW-14).
        """
        with self._lock:
            if flow.flow_id in self._flows:
                return False

            self._flows[flow.flow_id] = flow

            if flow.source_fact_id not in self._source_index:
                self._source_index[flow.source_fact_id] = []
            self._source_index[flow.source_fact_id].append(flow)

            if flow.sink_fact_id not in self._sink_index:
                self._sink_index[flow.sink_fact_id] = []
            self._sink_index[flow.sink_fact_id].append(flow)

            return True

    def get(self, flow_id: str) -> SemanticFlow | None:
        """Retrieves flow by flow_id."""
        with self._lock:
            return self._flows.get(flow_id)

    def get_by_source(self, source_fact_id: str) -> tuple[SemanticFlow, ...]:
        """Retrieves all flows for a source fact, deterministically sorted by flow_id."""
        with self._lock:
            flows = self._source_index.get(source_fact_id, [])
            return tuple(sorted(flows, key=lambda f: f.flow_id))

    def get_by_sink(self, sink_fact_id: str) -> tuple[SemanticFlow, ...]:
        """Retrieves all flows for a sink fact, deterministically sorted by flow_id."""
        with self._lock:
            flows = self._sink_index.get(sink_fact_id, [])
            return tuple(sorted(flows, key=lambda f: f.flow_id))

    def all(self) -> tuple[SemanticFlow, ...]:
        """Returns all flows deterministically sorted by flow_id."""
        with self._lock:
            return tuple(sorted(self._flows.values(), key=lambda f: f.flow_id))

    def count(self) -> int:
        """Returns total stored flows."""
        with self._lock:
            return len(self._flows)

    def clear(self) -> None:
        """Clears all stored flows."""
        with self._lock:
            self._flows.clear()
            self._source_index.clear()
            self._sink_index.clear()
