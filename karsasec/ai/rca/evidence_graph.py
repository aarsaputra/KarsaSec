"""Immutable Evidence Graph for Root Cause Analysis (E13-2).

Enforces Security Invariants:
  - G17: Every node/edge is derived strictly from SAST evidence or provenance.
  - G20: SSA versions ($x#1 vs $x#2) maintain distinct node identities.
  - G21: CallContext identities are preserved.
  - G22: Branch polarity is preserved.
  - G26: Byte-for-byte deterministic graph serialization and SHA-256 fingerprinting.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import hashlib
import json
from typing import Any

from karsasec.ai.evidence_context import SecurityFindingContext
from karsasec.graph.dataflow.semantic_evidence import SemanticEvidenceBundle


class GraphNodeType(StrEnum):
    """Categorical classification of evidence graph nodes."""

    SOURCE = "SOURCE"
    ASSIGNMENT = "ASSIGNMENT"
    TRANSFORMATION = "TRANSFORMATION"
    GUARD = "GUARD"
    SANITIZER = "SANITIZER"
    CALL = "CALL"
    RETURN = "RETURN"
    SINK = "SINK"
    SSA_VERSION = "SSA_VERSION"
    BRANCH = "BRANCH"
    FILE_BOUNDARY = "FILE_BOUNDARY"
    CROSS_FILE = "CROSS_FILE"


@dataclass(frozen=True, slots=True)
class EvidenceGraphNode:
    """Immutable node in the RCA evidence graph."""

    node_id: str
    node_type: GraphNodeType
    file_path: str = ""
    line_number: int = 0
    statement: str = ""
    variable_name: str = ""
    variable_version: str = ""
    call_context: str = "GLOBAL"
    branch_polarity: str = "UNKNOWN"
    proof_status: str = "UNKNOWN"
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": str(self.node_type),
            "file_path": self.file_path,
            "line_number": self.line_number,
            "statement": self.statement,
            "variable_name": self.variable_name,
            "variable_version": self.variable_version,
            "call_context": self.call_context,
            "branch_polarity": self.branch_polarity,
            "proof_status": self.proof_status,
            "description": self.description,
        }


@dataclass(frozen=True, slots=True)
class EvidenceGraphEdge:
    """Immutable directed edge connecting evidence graph nodes."""

    source_node_id: str
    target_node_id: str
    relation: str = "TAINT_FLOW"

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_node_id": self.source_node_id,
            "target_node_id": self.target_node_id,
            "relation": self.relation,
        }


@dataclass(frozen=True, slots=True)
class EvidenceGraph:
    """Immutable directed evidence graph for a security finding."""

    nodes: tuple[EvidenceGraphNode, ...]
    edges: tuple[EvidenceGraphEdge, ...]

    def get_node(self, node_id: str) -> EvidenceGraphNode | None:
        for node in self.nodes:
            if node.node_id == node_id:
                return node
        return None

    def canonical_fingerprint(self) -> str:
        """Computes deterministic SHA-256 fingerprint for the graph structure."""
        canonical_nodes = [n.to_dict() for n in sorted(self.nodes, key=lambda x: x.node_id)]
        canonical_edges = [e.to_dict() for e in sorted(self.edges, key=lambda x: (x.source_node_id, x.target_node_id))]
        data = {"nodes": canonical_nodes, "edges": canonical_edges}
        encoded = json.dumps(data, sort_keys=True).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @classmethod
    def from_context(
        cls,
        ctx: SecurityFindingContext,
        bundle: SemanticEvidenceBundle | None = None,
    ) -> EvidenceGraph:
        """Constructs an EvidenceGraph from SecurityFindingContext and optional SemanticEvidenceBundle."""
        nodes: list[EvidenceGraphNode] = []
        edges: list[EvidenceGraphEdge] = []

        # 1. Add Source node
        source_loc = ctx.source_location if ctx.source_location != "UNKNOWN" else f"{ctx.file_path}:1"
        s_file, s_line = source_loc.split(":")[:2] if ":" in source_loc else (ctx.file_path, "1")
        source_node_id = f"node_source_{ctx.finding_id}"
        nodes.append(
            EvidenceGraphNode(
                node_id=source_node_id,
                node_type=GraphNodeType.SOURCE,
                file_path=s_file,
                line_number=int(s_line) if s_line.isdigit() else 1,
                statement="User Taint Source",
                variable_name=ctx.variable_version.split("#")[0] if "#" in ctx.variable_version else ctx.variable_version,
                variable_version=ctx.variable_version,
                call_context=ctx.call_context,
                branch_polarity=ctx.branch_polarity,
                proof_status="PROVEN" if ctx.verdict_status == "VULNERABLE" else "UNKNOWN",
                description="Origin of user-controlled input taint",
            )
        )

        prev_node_id = source_node_id

        # 2. Add Provenance Path intermediate nodes if present
        for idx, prov in enumerate(ctx.provenance_path):
            prov_node_id = f"node_prov_{idx}_{ctx.finding_id}"
            p_file, p_line = prov.split(":")[:2] if ":" in prov else (prov, "0")
            n_type = GraphNodeType.CROSS_FILE if p_file != ctx.file_path else GraphNodeType.ASSIGNMENT
            nodes.append(
                EvidenceGraphNode(
                    node_id=prov_node_id,
                    node_type=n_type,
                    file_path=p_file,
                    line_number=int(p_line) if p_line.isdigit() else 0,
                    statement=f"Dataflow step {idx+1}",
                    variable_name=ctx.variable_version,
                    variable_version=ctx.variable_version,
                    call_context=ctx.call_context,
                    branch_polarity=ctx.branch_polarity,
                    proof_status="PROVEN",
                    description=f"Intermediate provenance step at {prov}",
                )
            )
            edges.append(EvidenceGraphEdge(source_node_id=prev_node_id, target_node_id=prov_node_id, relation="TAINT_FLOW"))
            prev_node_id = prov_node_id

        # 3. Add Sanitizer & Guard evidence nodes if present
        for s_idx, san in enumerate(ctx.sanitizer_evidence):
            san_node_id = f"node_sanitizer_{s_idx}_{ctx.finding_id}"
            nodes.append(
                EvidenceGraphNode(
                    node_id=san_node_id,
                    node_type=GraphNodeType.SANITIZER,
                    file_path=ctx.file_path,
                    line_number=ctx.line_number,
                    statement=san,
                    variable_name=ctx.variable_version,
                    variable_version=ctx.variable_version,
                    call_context=ctx.call_context,
                    branch_polarity=ctx.branch_polarity,
                    proof_status="PROVEN",
                    description=f"Sanitizer evidence: {san}",
                )
            )
            edges.append(EvidenceGraphEdge(source_node_id=prev_node_id, target_node_id=san_node_id, relation="SANITY_CHECK"))

        for g_idx, g_ev in enumerate(ctx.guard_evidence):
            g_node_id = f"node_guard_{g_idx}_{ctx.finding_id}"
            nodes.append(
                EvidenceGraphNode(
                    node_id=g_node_id,
                    node_type=GraphNodeType.GUARD,
                    file_path=ctx.file_path,
                    line_number=ctx.line_number,
                    statement=g_ev,
                    variable_name=ctx.variable_version,
                    variable_version=ctx.variable_version,
                    call_context=ctx.call_context,
                    branch_polarity=ctx.branch_polarity,
                    proof_status="PROVEN",
                    description=f"Control-flow guard evidence: {g_ev}",
                )
            )
            edges.append(EvidenceGraphEdge(source_node_id=prev_node_id, target_node_id=g_node_id, relation="CONTROL_GUARD"))

        # 4. Add Bundle evidences if supplied
        if bundle and bundle.evidences:
            for b_idx, ev in enumerate(bundle.evidences):
                b_node_id = f"node_bundle_{b_idx}_{ctx.finding_id}"
                nodes.append(
                    EvidenceGraphNode(
                        node_id=b_node_id,
                        node_type=GraphNodeType(ev.evidence_kind.value) if hasattr(ev.evidence_kind, "value") else GraphNodeType.ASSIGNMENT,
                        file_path=ev.file_path or ctx.file_path,
                        line_number=0,
                        statement=ev.statement,
                        variable_name=ev.var_name,
                        variable_version=ev.var_version or ctx.variable_version,
                        call_context=ctx.call_context,
                        branch_polarity=ev.branch_polarity or ctx.branch_polarity,
                        proof_status=str(ev.proof_status),
                        description=ev.description,
                    )
                )
                edges.append(EvidenceGraphEdge(source_node_id=prev_node_id, target_node_id=b_node_id, relation="SEMANTIC_EVIDENCE"))
                prev_node_id = b_node_id

        # 5. Add Sink node
        sink_node_id = f"node_sink_{ctx.finding_id}"
        nodes.append(
            EvidenceGraphNode(
                node_id=sink_node_id,
                node_type=GraphNodeType.SINK,
                file_path=ctx.file_path,
                line_number=ctx.line_number,
                statement=ctx.snippet,
                variable_name=ctx.variable_version,
                variable_version=ctx.variable_version,
                call_context=ctx.call_context,
                branch_polarity=ctx.branch_polarity,
                proof_status="PROVEN" if ctx.verdict_status == "VULNERABLE" else "NOT_PROVEN",
                description=f"Security Sink ({ctx.sink_category})",
            )
        )
        edges.append(EvidenceGraphEdge(source_node_id=prev_node_id, target_node_id=sink_node_id, relation="REACHES_SINK"))

        return EvidenceGraph(nodes=tuple(nodes), edges=tuple(edges))
