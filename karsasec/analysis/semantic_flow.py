"""Canonical SemanticFlow Data Model and Flow ID Computation for Sprint E11."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class FlowStatus(StrEnum):
    """Deterministic Flow Category for Interprocedural Taint Binding."""

    UNKNOWN = "UNKNOWN"
    CANDIDATE = "CANDIDATE"
    BLOCKED = "BLOCKED"
    CORRELATED = "CORRELATED"


def compute_flow_id(
    source_fact_id: str,
    sink_fact_id: str,
    path_node_ids: tuple[str, ...],
    call_context: tuple[tuple[str, str, str], ...],
    ssa_chain: tuple[tuple[str, str], ...],
    sanitizer_nodes: tuple[str, ...],
    schema_version: str = "1.0",
) -> str:
    """Computes a 64-character SHA-256 deterministic flow ID across process executions (INV-E11-FLOW-01,02)."""
    payload: dict[str, Any] = {
        "schema_version": schema_version,
        "source_fact_id": source_fact_id,
        "sink_fact_id": sink_fact_id,
        "path_node_ids": list(path_node_ids),
        "call_context": [list(ctx) for ctx in call_context],
        "ssa_chain": [list(ssa) for ssa in ssa_chain],
        "sanitizer_nodes": list(sanitizer_nodes),
    }
    canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class SemanticFlow:
    """Immutable, normalized semantic flow connecting source fact to sink fact."""

    flow_id: str
    source_fact_id: str
    sink_fact_id: str
    source_node_id: str
    sink_node_id: str
    path_node_ids: tuple[str, ...]
    call_context: tuple[tuple[str, str, str], ...]
    ssa_chain: tuple[tuple[str, str], ...]
    sanitizer_nodes: tuple[str, ...]
    confidence: float
    status: FlowStatus
    schema_version: str = "1.0"

    @classmethod
    def create(
        cls,
        source_fact_id: str,
        sink_fact_id: str,
        source_node_id: str,
        sink_node_id: str,
        path_node_ids: tuple[str, ...] | list[str] = (),
        call_context: tuple[tuple[str, str, str], ...] | list[tuple[str, str, str]] = (),
        ssa_chain: tuple[tuple[str, str], ...] | list[tuple[str, str]] = (),
        sanitizer_nodes: tuple[str, ...] | list[str] = (),
        confidence: float = 0.0,
        status: FlowStatus = FlowStatus.UNKNOWN,
        schema_version: str = "1.0",
    ) -> SemanticFlow:
        """Factory method that automatically computes deterministic SHA-256 flow_id."""
        path_tuple = tuple(path_node_ids)
        ctx_tuple = tuple(tuple(c) for c in call_context)
        ssa_tuple = tuple(tuple(s) for ssa in ssa_chain for s in (ssa,))
        san_tuple = tuple(sanitizer_nodes)

        fid = compute_flow_id(
            source_fact_id=source_fact_id,
            sink_fact_id=sink_fact_id,
            path_node_ids=path_tuple,
            call_context=ctx_tuple,
            ssa_chain=ssa_tuple,
            sanitizer_nodes=san_tuple,
            schema_version=schema_version,
        )

        clamped_confidence = max(0.0, min(1.0, round(confidence, 4)))

        return cls(
            flow_id=fid,
            source_fact_id=source_fact_id,
            sink_fact_id=sink_fact_id,
            source_node_id=source_node_id,
            sink_node_id=sink_node_id,
            path_node_ids=path_tuple,
            call_context=ctx_tuple,
            ssa_chain=ssa_tuple,
            sanitizer_nodes=san_tuple,
            confidence=clamped_confidence,
            status=status,
            schema_version=schema_version,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serializes SemanticFlow to dictionary deterministically."""
        return {
            "flow_id": self.flow_id,
            "source_fact_id": self.source_fact_id,
            "sink_fact_id": self.sink_fact_id,
            "source_node_id": self.source_node_id,
            "sink_node_id": self.sink_node_id,
            "path_node_ids": list(self.path_node_ids),
            "call_context": [list(ctx) for ctx in self.call_context],
            "ssa_chain": [list(ssa) for ssa in self.ssa_chain],
            "sanitizer_nodes": list(self.sanitizer_nodes),
            "confidence": self.confidence,
            "status": self.status.value,
            "schema_version": self.schema_version,
        }
