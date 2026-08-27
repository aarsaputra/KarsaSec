"""Canonical SemanticFact Data Model, Deterministic Identity, and SemanticFactStore for Sprint E10."""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from karsasec.cpg.models import CPGGraph

logger = logging.getLogger("karsasec.framework.semantic_fact")


class ConfidenceLevel(StrEnum):
    """Deterministic Confidence Category for Framework Facts."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class SemanticRole(StrEnum):
    """Normalized Framework-Independent Semantic Roles."""

    HTTP_ENDPOINT = "http_endpoint"
    HTTP_INPUT = "http_input"
    SECURITY_SINK = "security_sink"
    AUTHENTICATION_CHECK = "authentication_check"
    AUTHORIZATION_CHECK = "authorization_check"
    MIDDLEWARE = "middleware"
    SECURITY_CONFIGURATION = "security_configuration"
    GENERIC = "generic"


def compute_fact_id(
    framework: str,
    kind: str,
    file: str,
    line: int,
    symbol: str,
    metadata: dict[str, Any],
    schema_version: str = "1.0",
) -> str:
    """Computes a 64-character SHA-256 deterministic fact ID across process executions."""
    canonical_metadata = json.dumps(metadata, sort_keys=True, separators=(",", ":"))
    payload = f"{schema_version}:{framework.upper()}:{kind.lower()}:{file}:{line}:{symbol}:{canonical_metadata}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class SemanticFact:
    """Immutable, normalized semantic fact extracted from framework source code."""

    fact_id: str
    kind: str
    framework: str
    semantic_role: SemanticRole | str
    symbol: str
    file: str
    line: int
    column: int = 0
    node_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    source_kind: str | None = None
    sink_category: str | None = None
    confidence: float = 1.0
    confidence_level: ConfidenceLevel = ConfidenceLevel.HIGH
    parent_symbol: str | None = None
    call_context: str | None = None
    schema_version: str = "1.0"

    @classmethod
    def create(
        cls,
        kind: str,
        framework: str,
        symbol: str,
        file: str,
        line: int,
        semantic_role: SemanticRole | str = SemanticRole.GENERIC,
        column: int = 0,
        node_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        source_kind: str | None = None,
        sink_category: str | None = None,
        confidence: float = 1.0,
        confidence_level: ConfidenceLevel = ConfidenceLevel.HIGH,
        parent_symbol: str | None = None,
        call_context: str | None = None,
        schema_version: str = "1.0",
    ) -> SemanticFact:
        """Factory method that automatically computes deterministic SHA-256 fact_id."""
        meta = metadata or {}
        fid = compute_fact_id(
            framework=framework,
            kind=kind,
            file=file,
            line=line,
            symbol=symbol,
            metadata=meta,
            schema_version=schema_version,
        )
        return cls(
            fact_id=fid,
            kind=kind,
            framework=framework.upper(),
            semantic_role=semantic_role,
            symbol=symbol,
            file=file,
            line=line,
            column=column,
            node_id=node_id,
            metadata=dict(meta),
            source_kind=source_kind,
            sink_category=sink_category,
            confidence=round(confidence, 4),
            confidence_level=confidence_level,
            parent_symbol=parent_symbol,
            call_context=call_context,
            schema_version=schema_version,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serializes SemanticFact to dictionary deterministically."""
        return {
            "fact_id": self.fact_id,
            "kind": self.kind,
            "framework": self.framework,
            "semantic_role": str(self.semantic_role),
            "symbol": self.symbol,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "node_id": self.node_id,
            "metadata": dict(sorted(self.metadata.items())),
            "source_kind": self.source_kind,
            "sink_category": self.sink_category,
            "confidence": self.confidence,
            "confidence_level": self.confidence_level.value,
            "parent_symbol": self.parent_symbol,
            "call_context": self.call_context,
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SemanticFact:
        """Deserializes SemanticFact from dictionary."""
        return cls(
            fact_id=data["fact_id"],
            kind=data["kind"],
            framework=data["framework"],
            semantic_role=data.get("semantic_role", SemanticRole.GENERIC),
            symbol=data["symbol"],
            file=data["file"],
            line=data["line"],
            column=data.get("column", 0),
            node_id=data.get("node_id"),
            metadata=data.get("metadata", {}),
            source_kind=data.get("source_kind"),
            sink_category=data.get("sink_category"),
            confidence=data.get("confidence", 1.0),
            confidence_level=ConfidenceLevel(data.get("confidence_level", ConfidenceLevel.HIGH)),
            parent_symbol=data.get("parent_symbol"),
            call_context=data.get("call_context"),
            schema_version=data.get("schema_version", "1.0"),
        )


class SemanticFactStore:
    """Authoritative, decoupled store managing SemanticFact objects and CPG node attachments."""

    def __init__(self) -> None:
        self._facts: dict[str, SemanticFact] = {}
        self._node_facts: dict[str, list[SemanticFact]] = {}

    def add_fact(self, fact: SemanticFact, graph: CPGGraph | None = None) -> bool:
        """Adds a SemanticFact to the store, validating node existence and deduplicating.

        Returns True if fact was added, False if duplicate or rejected.
        """
        # INV-E10-SEM-13: Every node-bound SemanticFact MUST reference an existing authoritative CPGNode
        if graph is not None and fact.node_id is not None:
            if fact.node_id not in graph.nodes:
                logger.warning(
                    "Rejecting SemanticFact %s: node_id '%s' does not exist in CPGGraph",
                    fact.fact_id,
                    fact.node_id,
                )
                return False

        # INV-E10-SEM-15: Repeated extraction MUST NOT duplicate SemanticFacts
        if fact.fact_id in self._facts:
            return False

        self._facts[fact.fact_id] = fact
        if fact.node_id:
            if fact.node_id not in self._node_facts:
                self._node_facts[fact.node_id] = []
            self._node_facts[fact.node_id].append(fact)

        return True

    def get_fact(self, fact_id: str) -> SemanticFact | None:
        """Retrieves a fact by its deterministic fact_id."""
        return self._facts.get(fact_id)

    def get_facts_for_node(self, node_id: str) -> tuple[SemanticFact, ...]:
        """Retrieves all facts bound to a specific CPG node_id, ordered deterministically by fact_id."""
        facts = self._node_facts.get(node_id, [])
        return tuple(sorted(facts, key=lambda f: f.fact_id))

    def all_facts(self) -> tuple[SemanticFact, ...]:
        """Returns all stored facts ordered deterministically by fact_id."""
        return tuple(sorted(self._facts.values(), key=lambda f: f.fact_id))

    def clear(self) -> None:
        """Clears all stored facts."""
        self._facts.clear()
        self._node_facts.clear()

    def attach_to_cpg(self, graph: CPGGraph) -> int:
        """Attaches stored facts onto CPGNode.attributes for graph index availability.

        Returns the number of CPG nodes updated.
        """
        updated_count = 0
        for node_id, facts in self._node_facts.items():
            if node_id in graph.nodes:
                node = graph.nodes[node_id]
                # Store fact list under attribute
                node.attributes["semantic_facts"] = [f.to_dict() for f in self.get_facts_for_node(node_id)]

                # Non-destructive attribute propagation for CPGIndex pushdown
                for f in facts:
                    if f.source_kind and "source_kind" not in node.attributes:
                        node.attributes["source_kind"] = f.source_kind
                    if f.sink_category and "sink_category" not in node.attributes:
                        node.attributes["sink_category"] = f.sink_category
                    if f.semantic_role and "semantic_role" not in node.attributes:
                        node.attributes["semantic_role"] = str(f.semantic_role)
                updated_count += 1

        return updated_count

