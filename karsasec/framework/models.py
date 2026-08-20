"""Core models for Framework Semantic Layer (FrameworkDefinition, FrameworkMetadata, DetectorResult, FrameworkGraph)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class FrameworkType(StrEnum):
    """Supported framework type identifiers."""

    FLASK = "FLASK"
    DJANGO = "DJANGO"
    FASTAPI = "FASTAPI"
    EXPRESS = "EXPRESS"
    NEXTJS = "NEXTJS"
    LARAVEL = "LARAVEL"
    GIN = "GIN"
    GENERIC = "GENERIC"


class FrameworkCapability(StrEnum):
    """Capabilities provided by a framework semantic definition."""

    ROUTES = "ROUTES"
    MIDDLEWARE = "MIDDLEWARE"
    ORM = "ORM"
    TEMPLATE = "TEMPLATE"
    AUTH = "AUTH"
    AUTHZ = "AUTHZ"
    SESSION = "SESSION"
    COOKIE = "COOKIE"
    JWT = "JWT"
    CONFIG = "CONFIG"
    API = "API"
    WEBSOCKET = "WEBSOCKET"
    GRAPHQL = "GRAPHQL"


@dataclass(frozen=True)
class FrameworkVersion:
    """Framework version representation."""

    major: int = 1
    minor: int = 0
    patch: int = 0
    raw_version: str = "1.0.0"

    @classmethod
    def parse(cls, raw: str) -> FrameworkVersion:
        cleaned = raw.strip().lstrip("v^~>=")
        parts = cleaned.split(".")
        try:
            major = int(parts[0]) if len(parts) > 0 and parts[0].isdigit() else 1
            minor = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
            patch = int(parts[2].split("-")[0]) if len(parts) > 2 and parts[2].split("-")[0].isdigit() else 0
        except ValueError:
            major, minor, patch = 1, 0, 0
        return cls(major=major, minor=minor, patch=patch, raw_version=raw)


@dataclass(frozen=True)
class FrameworkDefinition:
    """Static framework definition registered in FrameworkRegistry."""

    id: str
    name: str
    language: str
    supported_versions: tuple[str, ...] = ()
    capabilities: tuple[FrameworkCapability, ...] = ()
    default_entrypoints: tuple[str, ...] = ()
    default_config_files: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "language": self.language,
            "supported_versions": list(self.supported_versions),
            "capabilities": [c.value for c in self.capabilities],
            "default_entrypoints": list(self.default_entrypoints),
            "default_config_files": list(self.default_config_files),
        }


@dataclass(frozen=True)
class DetectorResult:
    """Result produced by FrameworkDetector containing confidence score and evidence."""

    framework: FrameworkType
    confidence: float
    reason: str
    evidence: tuple[str, ...] = ()
    version: FrameworkVersion = field(default_factory=FrameworkVersion)

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework": self.framework.value,
            "confidence": round(self.confidence, 4),
            "reason": self.reason,
            "evidence": list(self.evidence),
            "version": self.version.raw_version,
        }


@dataclass(frozen=True)
class FrameworkMetadata:
    """Analysis metadata capturing runtime detection statistics."""

    detected_frameworks: tuple[DetectorResult, ...] = ()
    entrypoints: tuple[str, ...] = ()
    config_files: tuple[str, ...] = ()
    statistics: dict[str, Any] = field(default_factory=dict)
    generated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    engine_version: str = "1.0.0"

    def to_dict(self) -> dict[str, Any]:
        return {
            "detected_frameworks": [d.to_dict() for d in self.detected_frameworks],
            "entrypoints": list(self.entrypoints),
            "config_files": list(self.config_files),
            "statistics": self.statistics,
            "generated_at": self.generated_at,
            "engine_version": self.engine_version,
        }


class FrameworkNodeType(StrEnum):
    """Node types supported in Sprint E10-1 FrameworkGraph."""

    FRAMEWORK = "FRAMEWORK"
    ENTRYPOINT = "ENTRYPOINT"
    CONFIG = "CONFIG"
    MODULE = "MODULE"


@dataclass(frozen=True)
class FrameworkNode:
    """Immutable node in FrameworkGraph."""

    id: str
    node_type: FrameworkNodeType
    name: str
    language: str = "Generic"
    version: str = "1.0.0"
    labels: tuple[str, ...] = ()
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "node_type": self.node_type.value,
            "name": self.name,
            "language": self.language,
            "version": self.version,
            "labels": list(self.labels),
            "attributes": self.attributes,
        }


@dataclass(frozen=True)
class FrameworkEdge:
    """Immutable edge in FrameworkGraph."""

    source_id: str
    target_id: str
    edge_type: str = "CONTAINS"
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type,
            "attributes": self.attributes,
        }


class FrameworkGraph:
    """Graph structure representing framework components and topology in CPG."""

    def __init__(self) -> None:
        self.nodes: dict[str, FrameworkNode] = {}
        self.edges: list[FrameworkEdge] = []
        self.outgoing_edges: dict[str, list[FrameworkEdge]] = {}
        self.incoming_edges: dict[str, list[FrameworkEdge]] = {}

    def add_node(self, node: FrameworkNode) -> None:
        self.nodes[node.id] = node
        if node.id not in self.outgoing_edges:
            self.outgoing_edges[node.id] = []
        if node.id not in self.incoming_edges:
            self.incoming_edges[node.id] = []

    def add_edge(self, edge: FrameworkEdge) -> None:
        self.edges.append(edge)
        if edge.source_id in self.nodes:
            self.outgoing_edges.setdefault(edge.source_id, []).append(edge)
        if edge.target_id in self.nodes:
            self.incoming_edges.setdefault(edge.target_id, []).append(edge)

    def get_outgoing_edges(self, node_id: str) -> list[FrameworkEdge]:
        return self.outgoing_edges.get(node_id, [])

    def get_incoming_edges(self, node_id: str) -> list[FrameworkEdge]:
        return self.incoming_edges.get(node_id, [])

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FrameworkGraph:
        graph = cls()
        for raw_n in data.get("nodes", []):
            node = FrameworkNode(
                id=raw_n["id"],
                node_type=FrameworkNodeType(raw_n["node_type"]),
                name=raw_n["name"],
                language=raw_n.get("language", "Generic"),
                version=raw_n.get("version", "1.0.0"),
                labels=tuple(raw_n.get("labels", [])),
                attributes=raw_n.get("attributes", {}),
            )
            graph.add_node(node)
        for raw_e in data.get("edges", []):
            edge = FrameworkEdge(
                source_id=raw_e["source_id"],
                target_id=raw_e["target_id"],
                edge_type=raw_e.get("edge_type", "CONTAINS"),
                attributes=raw_e.get("attributes", {}),
            )
            graph.add_edge(edge)
        return graph
