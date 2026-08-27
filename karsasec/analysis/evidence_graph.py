"""EvidenceGraph data model, EvidenceNode, EvidenceEdge, and deterministic identity algorithms for Sprint E13."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class EvidenceNodeType(StrEnum):
    """Types of nodes in the Vulnerability Evidence Graph."""

    SOURCE = "SOURCE"
    TRANSFORM = "TRANSFORM"
    SANITIZER = "SANITIZER"
    CALLSITE = "CALLSITE"
    SINK = "SINK"
    FINDING = "FINDING"
    CLUSTER = "CLUSTER"


class EvidenceEdgeType(StrEnum):
    """Types of directed edges in the Vulnerability Evidence Graph."""

    SOURCE_TO_TRANSFORM = "SOURCE_TO_TRANSFORM"
    TRANSFORM_TO_TRANSFORM = "TRANSFORM_TO_TRANSFORM"
    TRANSFORM_TO_SINK = "TRANSFORM_TO_SINK"
    SOURCE_TO_SINK = "SOURCE_TO_SINK"
    CALLER_TO_CALLEE = "CALLER_TO_CALLEE"
    SANITIZER_ON_FLOW = "SANITIZER_ON_FLOW"
    FINDING_SUPPORTS_FLOW = "FINDING_SUPPORTS_FLOW"
    FINDING_SUPPORTS_CLUSTER = "FINDING_SUPPORTS_CLUSTER"


def compute_evidence_node_id(node_type: str | EvidenceNodeType, identity_payload: Any) -> str:
    """Computes a deterministic SHA-256 evidence node ID."""
    if isinstance(identity_payload, (dict, list, tuple)):
        canonical = json.dumps(identity_payload, sort_keys=True, separators=(",", ":"))
    else:
        canonical = str(identity_payload)

    raw = f"E13-NODE:{str(node_type)}:{canonical}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def compute_evidence_edge_id(source_node_id: str, target_node_id: str, edge_type: str | EvidenceEdgeType) -> str:
    """Computes a deterministic SHA-256 evidence edge ID."""
    raw = f"E13-EDGE:{source_node_id}:{target_node_id}:{str(edge_type)}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class EvidenceNode:
    """Immutable Node representation in Evidence Graph."""

    node_id: str
    node_type: EvidenceNodeType
    label: str
    attributes: tuple[tuple[str, str], ...] = ()

    @classmethod
    def create(
        cls,
        node_type: EvidenceNodeType,
        label: str,
        identity_payload: Any,
        attributes: Mapping[str, Any] | Sequence[tuple[str, str]] | None = None,
    ) -> EvidenceNode:
        """Factory creating EvidenceNode with deterministic node_id."""
        nid = compute_evidence_node_id(node_type, identity_payload)

        norm_attrs: list[tuple[str, str]] = []
        if isinstance(attributes, Mapping):
            norm_attrs = sorted((str(k), str(v)) for k, v in attributes.items())
        elif isinstance(attributes, Sequence):
            norm_attrs = sorted((str(k), str(v)) for k, v in attributes)

        return cls(
            node_id=nid,
            node_type=node_type,
            label=label,
            attributes=tuple(norm_attrs),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serializes node to dictionary."""
        return {
            "node_id": self.node_id,
            "node_type": self.node_type.value,
            "label": self.label,
            "attributes": dict(self.attributes),
        }


@dataclass(frozen=True)
class EvidenceEdge:
    """Immutable Edge representation linking evidence nodes."""

    edge_id: str
    source_node_id: str
    target_node_id: str
    edge_type: EvidenceEdgeType
    attributes: tuple[tuple[str, str], ...] = ()

    @classmethod
    def create(
        cls,
        source_node_id: str,
        target_node_id: str,
        edge_type: EvidenceEdgeType,
        attributes: Mapping[str, Any] | Sequence[tuple[str, str]] | None = None,
    ) -> EvidenceEdge:
        """Factory creating EvidenceEdge with deterministic edge_id."""
        eid = compute_evidence_edge_id(source_node_id, target_node_id, edge_type)

        norm_attrs: list[tuple[str, str]] = []
        if isinstance(attributes, Mapping):
            norm_attrs = sorted((str(k), str(v)) for k, v in attributes.items())
        elif isinstance(attributes, Sequence):
            norm_attrs = sorted((str(k), str(v)) for k, v in attributes)

        return cls(
            edge_id=eid,
            source_node_id=source_node_id,
            target_node_id=target_node_id,
            edge_type=edge_type,
            attributes=tuple(norm_attrs),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serializes edge to dictionary."""
        return {
            "edge_id": self.edge_id,
            "source_node_id": self.source_node_id,
            "target_node_id": self.target_node_id,
            "edge_type": self.edge_type.value,
            "attributes": dict(self.attributes),
        }


@dataclass(frozen=True)
class EvidenceGraph:
    """Immutable Evidence Graph preserving complete forensic auditability across findings and clusters."""

    nodes: tuple[EvidenceNode, ...] = field(default_factory=tuple)
    edges: tuple[EvidenceEdge, ...] = field(default_factory=tuple)

    @classmethod
    def create(
        cls,
        nodes: Sequence[EvidenceNode] = (),
        edges: Sequence[EvidenceEdge] = (),
    ) -> EvidenceGraph:
        """Factory constructing a canonical EvidenceGraph with deterministic node and edge sorting."""
        node_map: dict[str, EvidenceNode] = {}
        for n in nodes:
            node_map[n.node_id] = n

        edge_map: dict[str, EvidenceEdge] = {}
        for e in edges:
            edge_map[e.edge_id] = e

        sorted_nodes = tuple(node_map[k] for k in sorted(node_map.keys()))
        sorted_edges = tuple(edge_map[k] for k in sorted(edge_map.keys()))

        return cls(nodes=sorted_nodes, edges=sorted_edges)

    def to_dict(self) -> dict[str, Any]:
        """Serializes entire graph to dictionary."""
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
        }
