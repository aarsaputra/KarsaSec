"""Authoritative Remediation Provenance Graph Engine for KarsaSec AI Engine (Sprint E13-5 Phase 2).

Defines an immutable, cryptographically deterministic provenance graph representing the complete
remediation evidence chain: Finding -> Evidence -> RCA -> Strategy -> Proposal -> ApprovalToken -> SourceSnapshot -> ApplicationResult -> VerificationResult.

Enforces Security Invariants:
  - P1: Immutable Provenance (Frozen dataclasses; zero in-place graph/node mutation).
  - P2-P4: Explicit Node Identity & Chain Continuity (No orphan nodes; explicit predecessors).
  - P5-P6: Deterministic Canonical Fingerprinting (SHA-256; insertion-order and PYTHONHASHSEED invariant).
  - P7-P15: Cryptographic Evidence Binding (Binds domain artifacts byte-for-byte).
  - P8: No Security Verdict Authority (Observational audit layer only; cannot grant VERIFIED_FIXED).
  - P16: No Auto-Repair / Execution Capability (Zero subprocess, shell, git execution).
  - P17: No Secret Leakage (Raw source code, tokens, credentials strictly excluded from metadata).
  - P18: Deterministic Graph Fingerprint (Derived from canonical graph topology & node fingerprints).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import hashlib
from typing import Any

from karsasec.ai.rca.models import RootCauseAnalysis
from karsasec.ai.remediation.approval import PatchApprovalToken
from karsasec.ai.remediation.applier import ApplicationResult
from karsasec.ai.remediation.models import PatchProposal, RemediationStrategy
from karsasec.ai.remediation.snapshot import SourceSnapshot
from karsasec.ai.remediation.verification import VerificationResult
from karsasec.core.finding.model import Finding


class ProvenanceNodeType(StrEnum):
    """Categorical types of remediation provenance nodes."""

    FINDING = "FINDING"
    EVIDENCE = "EVIDENCE"
    RCA = "RCA"
    STRATEGY = "STRATEGY"
    PROPOSAL = "PROPOSAL"
    APPROVAL_TOKEN = "APPROVAL_TOKEN"
    SOURCE_SNAPSHOT = "SOURCE_SNAPSHOT"
    APPLICATION_RESULT = "APPLICATION_RESULT"
    VERIFICATION_RESULT = "VERIFICATION_RESULT"


@dataclass(frozen=True, slots=True)
class ProvenanceNode:
    """Immutable single node in the remediation provenance graph (P1, P2)."""

    node_id: str
    node_type: ProvenanceNodeType
    fingerprint: str
    predecessor_node_ids: tuple[str, ...]
    metadata: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not self.node_id or not self.node_id.strip():
            raise ValueError("node_id cannot be empty.")

        expected_fp = self.compute_fingerprint(
            node_id=self.node_id,
            node_type=self.node_type,
            predecessor_node_ids=self.predecessor_node_ids,
            metadata=self.metadata,
        )
        if self.fingerprint != expected_fp:
            raise ValueError(
                f"Tampered or invalid node fingerprint for '{self.node_id}'. "
                f"Expected '{expected_fp}', got '{self.fingerprint}'."
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": str(self.node_type),
            "fingerprint": self.fingerprint,
            "predecessor_node_ids": list(self.predecessor_node_ids),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProvenanceNode:
        meta_dict = data.get("metadata", {})
        meta_tuple = tuple(sorted((str(k), str(v)) for k, v in meta_dict.items()))
        node_id = data["node_id"]
        node_type = ProvenanceNodeType(data["node_type"])
        preds = tuple(data.get("predecessor_node_ids", []))
        fp = data.get("fingerprint") or cls.compute_fingerprint(
            node_id=node_id,
            node_type=node_type,
            predecessor_node_ids=preds,
            metadata=meta_tuple,
        )
        return cls(
            node_id=node_id,
            node_type=node_type,
            fingerprint=fp,
            predecessor_node_ids=preds,
            metadata=meta_tuple,
        )

    @staticmethod
    def compute_fingerprint(
        node_id: str,
        node_type: ProvenanceNodeType,
        predecessor_node_ids: tuple[str, ...],
        metadata: tuple[tuple[str, str], ...],
    ) -> str:
        """Compute canonical, byte-for-byte SHA-256 fingerprint for a provenance node (P5, P6)."""
        sorted_preds = "|".join(sorted(predecessor_node_ids))
        sorted_meta = "|".join(f"{k}:{v}" for k, v in sorted(metadata))
        raw = f"{node_id}|{node_type.value}|{sorted_preds}|{sorted_meta}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    # Factory constructors binding domain artifacts (P7-P15)

    @classmethod
    def create_finding_node(cls, finding: Finding, node_id: str | None = None) -> ProvenanceNode:
        nid = node_id or f"prov_finding_{finding.finding_id}"
        meta = (
            ("finding_id", finding.finding_id),
            ("rule_id", finding.rule_id),
            ("cwe_id", finding.cwe_id or "UNKNOWN"),
            ("file_path", str(finding.file_path).replace("\\", "/")),
            ("finding_fingerprint", finding.fingerprint),
        )
        sorted_meta = tuple(sorted(meta))
        fp = cls.compute_fingerprint(nid, ProvenanceNodeType.FINDING, (), sorted_meta)
        return cls(
            node_id=nid,
            node_type=ProvenanceNodeType.FINDING,
            fingerprint=fp,
            predecessor_node_ids=(),
            metadata=sorted_meta,
        )

    @classmethod
    def create_evidence_node(cls, finding: Finding, predecessor_id: str, node_id: str | None = None) -> ProvenanceNode:
        nid = node_id or f"prov_ev_{finding.finding_id}"
        line = str(finding.evidence.line) if finding.evidence else "0"
        sym = getattr(finding.evidence, "variable_name", getattr(finding.evidence, "snippet", "UNKNOWN")) if finding.evidence else "UNKNOWN"
        meta = (
            ("finding_id", finding.finding_id),
            ("evidence_fingerprint", finding.verdict.evidence_fingerprint if finding.verdict else finding.fingerprint),
            ("line_number", line),
            ("affected_symbol", str(sym)),
        )
        sorted_meta = tuple(sorted(meta))
        preds = (predecessor_id,)
        fp = cls.compute_fingerprint(nid, ProvenanceNodeType.EVIDENCE, preds, sorted_meta)
        return cls(
            node_id=nid,
            node_type=ProvenanceNodeType.EVIDENCE,
            fingerprint=fp,
            predecessor_node_ids=preds,
            metadata=sorted_meta,
        )

    @classmethod
    def create_rca_node(cls, rca: RootCauseAnalysis, predecessor_id: str, node_id: str | None = None) -> ProvenanceNode:
        nid = node_id or f"prov_rca_{rca.finding_id}"
        meta = (
            ("finding_id", rca.finding_id),
            ("rca_fingerprint", rca.rca_fingerprint),
            ("root_cause_category", str(rca.root_cause_category)),
            ("reflection_status", str(rca.reflection_status)),
            ("false_positive_risk", str(rca.false_positive_risk)),
        )
        sorted_meta = tuple(sorted(meta))
        preds = (predecessor_id,)
        fp = cls.compute_fingerprint(nid, ProvenanceNodeType.RCA, preds, sorted_meta)
        return cls(
            node_id=nid,
            node_type=ProvenanceNodeType.RCA,
            fingerprint=fp,
            predecessor_node_ids=preds,
            metadata=sorted_meta,
        )

    @classmethod
    def create_strategy_node(cls, strategy: RemediationStrategy, predecessor_id: str, node_id: str | None = None) -> ProvenanceNode:
        nid = node_id or f"prov_strat_{strategy.finding_id}"
        meta = (
            ("finding_id", strategy.finding_id),
            ("strategy_fingerprint", strategy.strategy_fingerprint),
            ("strategy_type", str(strategy.strategy_type)),
            ("target_file", strategy.target_file.replace("\\", "/")),
        )
        sorted_meta = tuple(sorted(meta))
        preds = (predecessor_id,)
        fp = cls.compute_fingerprint(nid, ProvenanceNodeType.STRATEGY, preds, sorted_meta)
        return cls(
            node_id=nid,
            node_type=ProvenanceNodeType.STRATEGY,
            fingerprint=fp,
            predecessor_node_ids=preds,
            metadata=sorted_meta,
        )

    @classmethod
    def create_proposal_node(cls, proposal: PatchProposal, predecessor_id: str, node_id: str | None = None) -> ProvenanceNode:
        nid = node_id or f"prov_prop_{proposal.proposal_id}"
        files_str = "|".join(sorted(f.replace("\\", "/") for f in proposal.target_files))
        meta = (
            ("proposal_id", proposal.proposal_id),
            ("finding_id", proposal.finding_id),
            ("proposal_fingerprint", proposal.proposal_fingerprint),
            ("validation_status", str(proposal.validation_status)),
            ("target_files", files_str),
        )
        sorted_meta = tuple(sorted(meta))
        preds = (predecessor_id,)
        fp = cls.compute_fingerprint(nid, ProvenanceNodeType.PROPOSAL, preds, sorted_meta)
        return cls(
            node_id=nid,
            node_type=ProvenanceNodeType.PROPOSAL,
            fingerprint=fp,
            predecessor_node_ids=preds,
            metadata=sorted_meta,
        )

    @classmethod
    def create_approval_token_node(cls, token: PatchApprovalToken, predecessor_id: str, node_id: str | None = None) -> ProvenanceNode:
        nid = node_id or f"prov_tok_{token.token_id}"
        meta = (
            ("token_id", token.token_id),
            ("finding_id", token.finding_id),
            ("proposal_fingerprint", token.proposal_fingerprint),
            ("token_fingerprint", token.token_fingerprint),
            ("source_snapshot_hash", token.source_snapshot_hash),
            ("approved_by", token.approved_by),
            ("repository_identity", token.repository_identity),
        )
        sorted_meta = tuple(sorted(meta))
        preds = (predecessor_id,)
        fp = cls.compute_fingerprint(nid, ProvenanceNodeType.APPROVAL_TOKEN, preds, sorted_meta)
        return cls(
            node_id=nid,
            node_type=ProvenanceNodeType.APPROVAL_TOKEN,
            fingerprint=fp,
            predecessor_node_ids=preds,
            metadata=sorted_meta,
        )

    @classmethod
    def create_source_snapshot_node(cls, snapshot: SourceSnapshot, predecessor_id: str, node_id: str | None = None) -> ProvenanceNode:
        nid = node_id or f"prov_snap_{snapshot.aggregate_hash[:12]}"
        meta = (
            ("aggregate_hash", snapshot.aggregate_hash),
            ("repository_root", str(snapshot.repository_root).replace("\\", "/")),
            ("file_count", str(len(snapshot.file_snapshots))),
        )
        sorted_meta = tuple(sorted(meta))
        preds = (predecessor_id,)
        fp = cls.compute_fingerprint(nid, ProvenanceNodeType.SOURCE_SNAPSHOT, preds, sorted_meta)
        return cls(
            node_id=nid,
            node_type=ProvenanceNodeType.SOURCE_SNAPSHOT,
            fingerprint=fp,
            predecessor_node_ids=preds,
            metadata=sorted_meta,
        )

    @classmethod
    def create_application_node(
        cls,
        app_result: ApplicationResult,
        predecessor_ids: tuple[str, ...],
        node_id: str | None = None,
    ) -> ProvenanceNode:
        nid = node_id or f"prov_app_{app_result.transaction_id}"
        meta = (
            ("transaction_id", app_result.transaction_id),
            ("finding_id", app_result.finding_id),
            ("proposal_fingerprint", app_result.proposal_fingerprint),
            ("status", str(app_result.status)),
            ("pre_apply_snapshot_hash", app_result.pre_apply_snapshot_hash),
            ("post_apply_snapshot_hash", app_result.post_apply_snapshot_hash),
        )
        sorted_meta = tuple(sorted(meta))
        sorted_preds = tuple(sorted(predecessor_ids))
        fp = cls.compute_fingerprint(nid, ProvenanceNodeType.APPLICATION_RESULT, sorted_preds, sorted_meta)
        return cls(
            node_id=nid,
            node_type=ProvenanceNodeType.APPLICATION_RESULT,
            fingerprint=fp,
            predecessor_node_ids=sorted_preds,
            metadata=sorted_meta,
        )

    @classmethod
    def create_verification_node(
        cls,
        ver_result: VerificationResult,
        predecessor_id: str,
        proposal_fingerprint: str,
        source_snapshot_hash: str,
        post_apply_snapshot_hash: str,
        verification_fingerprint: str,
        node_id: str | None = None,
    ) -> ProvenanceNode:
        nid = node_id or f"prov_ver_{ver_result.verification_id}"
        meta = (
            ("verification_id", ver_result.verification_id),
            ("finding_id", ver_result.finding_id),
            ("status", str(ver_result.status)),
            ("proposal_fingerprint", proposal_fingerprint),
            ("source_snapshot_hash", source_snapshot_hash),
            ("post_apply_snapshot_hash", post_apply_snapshot_hash),
            ("verification_fingerprint", verification_fingerprint),
        )
        sorted_meta = tuple(sorted(meta))
        preds = (predecessor_id,)
        fp = cls.compute_fingerprint(nid, ProvenanceNodeType.VERIFICATION_RESULT, preds, sorted_meta)
        return cls(
            node_id=nid,
            node_type=ProvenanceNodeType.VERIFICATION_RESULT,
            fingerprint=fp,
            predecessor_node_ids=preds,
            metadata=sorted_meta,
        )


@dataclass(frozen=True, slots=True)
class RemediationProvenanceGraph:
    """Immutable, cryptographically deterministic provenance graph (P1, P3, P4, P18)."""

    nodes: tuple[ProvenanceNode, ...] = ()

    def __post_init__(self) -> None:
        self.validate_integrity()

    def get_node(self, node_id: str) -> ProvenanceNode | None:
        """Retrieve node by ID."""
        for n in self.nodes:
            if n.node_id == node_id:
                return n
        return None

    @property
    def root_nodes(self) -> tuple[ProvenanceNode, ...]:
        """Returns root nodes (nodes with zero predecessors)."""
        return tuple(n for n in self.nodes if not n.predecessor_node_ids)

    @property
    def terminal_nodes(self) -> tuple[ProvenanceNode, ...]:
        """Returns terminal nodes (nodes that are not predecessors to any other node)."""
        all_preds = {pred for n in self.nodes for pred in n.predecessor_node_ids}
        return tuple(n for n in self.nodes if n.node_id not in all_preds)

    @property
    def graph_fingerprint(self) -> str:
        """Compute canonical SHA-256 fingerprint for entire provenance graph (P5, P18).

        Insertion-order and PYTHONHASHSEED invariant.
        """
        sorted_nodes = sorted(self.nodes, key=lambda n: n.node_id)
        canon_records: list[str] = []
        for n in sorted_nodes:
            sorted_preds = "|".join(sorted(n.predecessor_node_ids))
            canon_records.append(f"{n.node_id}:{n.node_type.value}:{n.fingerprint}:{sorted_preds}")
        raw = "||".join(canon_records)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def add_node(self, node: ProvenanceNode) -> RemediationProvenanceGraph:
        """Add a node and return a NEW immutable RemediationProvenanceGraph instance (P1).

        Enforces duplicate check, orphan check, self-reference check, and cycle check.
        """
        existing_ids = {n.node_id for n in self.nodes}
        if node.node_id in existing_ids:
            raise ValueError(f"Duplicate node_id '{node.node_id}' in provenance graph.")

        if node.node_id in node.predecessor_node_ids:
            raise ValueError(f"Self-reference detected for node_id '{node.node_id}'.")

        for pred_id in node.predecessor_node_ids:
            if pred_id not in existing_ids:
                raise ValueError(
                    f"Orphan node error: Predecessor '{pred_id}' for node '{node.node_id}' does not exist in graph."
                )

        new_nodes = self.nodes + (node,)
        # Cycle check via Kahn's algorithm or DFS on temporary graph
        self._detect_cycle(new_nodes)
        return RemediationProvenanceGraph(nodes=new_nodes)

    @staticmethod
    def _detect_cycle(nodes: tuple[ProvenanceNode, ...]) -> None:
        """Verify topological order and detect cycles."""
        adj: dict[str, list[str]] = {n.node_id: [] for n in nodes}
        in_degree: dict[str, int] = {n.node_id: 0 for n in nodes}

        for n in nodes:
            for pred in n.predecessor_node_ids:
                if pred in adj:
                    adj[pred].append(n.node_id)
                    in_degree[n.node_id] += 1

        queue = [nid for nid, deg in in_degree.items() if deg == 0]
        visited_count = 0

        while queue:
            curr = queue.pop(0)
            visited_count += 1
            for neighbor in adj.get(curr, []):
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)

        if visited_count != len(nodes):
            raise ValueError("Cycle detected in provenance graph.")

    def validate_integrity(self) -> tuple[bool, str]:
        """Validate structural integrity and cryptographic consistency of graph."""
        seen_ids: set[str] = set()
        for node in self.nodes:
            if node.node_id in seen_ids:
                raise ValueError(f"Duplicate node_id '{node.node_id}'.")
            seen_ids.add(node.node_id)

            if node.node_id in node.predecessor_node_ids:
                raise ValueError(f"Self-reference in node '{node.node_id}'.")

            # Verify node fingerprint calculation
            expected_fp = ProvenanceNode.compute_fingerprint(
                node_id=node.node_id,
                node_type=node.node_type,
                predecessor_node_ids=node.predecessor_node_ids,
                metadata=node.metadata,
            )
            if node.fingerprint != expected_fp:
                raise ValueError(f"Node fingerprint mismatch for node '{node.node_id}'.")

        for node in self.nodes:
            for pred in node.predecessor_node_ids:
                if pred not in seen_ids:
                    raise ValueError(f"Orphan predecessor '{pred}' referenced by node '{node.node_id}'.")

        self._detect_cycle(self.nodes)
        return True, "VALID"

    def to_dict(self) -> dict[str, Any]:
        """Export canonical dictionary representation."""
        sorted_nodes = sorted(self.nodes, key=lambda n: n.node_id)
        return {
            "graph_fingerprint": self.graph_fingerprint,
            "node_count": len(self.nodes),
            "nodes": [n.to_dict() for n in sorted_nodes],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RemediationProvenanceGraph:
        """Reconstruct RemediationProvenanceGraph from canonical dictionary data."""
        nodes_data = data.get("nodes", [])
        raw_nodes = [ProvenanceNode.from_dict(nd) for nd in nodes_data]

        # Topological sort to construct graph without orphan errors
        adj: dict[str, list[ProvenanceNode]] = {}
        node_map: dict[str, ProvenanceNode] = {n.node_id: n for n in raw_nodes}
        in_degree: dict[str, int] = {n.node_id: 0 for n in raw_nodes}

        for n in raw_nodes:
            for pred in n.predecessor_node_ids:
                in_degree[n.node_id] += 1
                if pred not in adj:
                    adj[pred] = []
                adj[pred].append(n)

        queue = [nid for nid, deg in in_degree.items() if deg == 0]
        sorted_nodes: list[ProvenanceNode] = []

        while queue:
            curr_id = queue.pop(0)
            sorted_nodes.append(node_map[curr_id])
            for child in adj.get(curr_id, []):
                in_degree[child.node_id] -= 1
                if in_degree[child.node_id] == 0:
                    queue.append(child.node_id)

        graph = cls()
        for node in sorted_nodes:
            graph = graph.add_node(node)

        return graph
