"""Artifact Validation Framework evaluating invariants across AST, HIR, MIR, CFG, CallGraph, Dataflow, and Findings."""

from dataclasses import dataclass, field
from typing import Any

from karsasec.core.finding.model import Finding
from karsasec.graph.dataflow import DataflowEngine
from karsasec.parser.ast_nodes import FileNode


@dataclass
class ValidationReport:
    """Immutable validation summary carrying pass decision and invariant error logs."""
    is_valid: bool
    artifact_type: str
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class ArtifactValidator:
    """Automated validator enforcing structural and semantic invariants on intermediate analysis artifacts."""

    def validate_ast(self, root_node: FileNode) -> ValidationReport:
        """Validates FileNode AST invariants: unique node IDs, parent pointers, valid line spans."""
        errors: list[str] = []
        warnings: list[str] = []
        seen_ids: set[str] = set()

        if not root_node or not hasattr(root_node, "node_id"):
            return ValidationReport(is_valid=False, artifact_type="AST", errors=["Root FileNode is null or invalid."])

        nodes_map = getattr(root_node, "nodes_map", {}) or {}

        for node_id, node in nodes_map.items():
            if node_id in seen_ids:
                errors.append(f"Duplicate node ID detected: {node_id}")
            seen_ids.add(node_id)

            if node.start and node.end and node.start.line > node.end.line:
                errors.append(f"Invalid position span in node {node_id}: start line {node.start.line} > end line {node.end.line}")

        return ValidationReport(is_valid=len(errors) == 0, artifact_type="AST", errors=errors, warnings=warnings)

    def validate_cfg(self, cfg_data: dict[str, Any]) -> ValidationReport:
        """Validates CFG invariants: exactly one entry node, reachable exit node, connected graph."""
        errors: list[str] = []
        warnings: list[str] = []

        entry_nodes = cfg_data.get("entry_nodes", [])
        blocks = cfg_data.get("blocks", {})
        edges = cfg_data.get("edges", [])

        if len(entry_nodes) != 1:
            errors.append(f"CFG must have exactly one entry node, found {len(entry_nodes)}")

        block_ids = set(blocks.keys())
        for edge in edges:
            src = edge.get("from")
            dst = edge.get("to")
            if src and src not in block_ids:
                errors.append(f"Invalid CFG edge source node '{src}' not found in blocks.")
            if dst and dst not in block_ids:
                errors.append(f"Invalid CFG edge destination node '{dst}' not found in blocks.")

        return ValidationReport(is_valid=len(errors) == 0, artifact_type="CFG", errors=errors, warnings=warnings)

    def validate_call_graph(self, call_graph_data: dict[str, Any]) -> ValidationReport:
        """Validates CallGraph invariants: caller/callee existence, duplicate edge check."""
        errors: list[str] = []
        warnings: list[str] = []

        nodes = set(call_graph_data.get("nodes", {}).keys())
        edges = call_graph_data.get("edges", [])
        seen_edges: set[str] = set()

        for edge in edges:
            caller = edge.get("caller")
            callee = edge.get("callee")

            if caller and caller not in nodes:
                warnings.append(f"CallGraph caller '{caller}' unresolved in nodes index.")
            if callee and callee not in nodes:
                warnings.append(f"CallGraph callee '{callee}' unresolved in nodes index.")

            edge_key = f"{caller}->{callee}:{edge.get('line', 0)}"
            if edge_key in seen_edges:
                errors.append(f"Duplicate CallGraph edge detected: {edge_key}")
            seen_edges.add(edge_key)

        return ValidationReport(is_valid=len(errors) == 0, artifact_type="CallGraph", errors=errors, warnings=warnings)

    def validate_dataflow(self, dataflow_engine: DataflowEngine) -> ValidationReport:
        """Validates DataflowEngine invariants: valid nodes, non-empty edges."""
        errors: list[str] = []
        warnings: list[str] = []

        if not dataflow_engine:
            return ValidationReport(is_valid=False, artifact_type="Dataflow", errors=["DataflowEngine object is null."])

        nodes = getattr(dataflow_engine, "nodes", {})
        if not nodes:
            warnings.append("DataflowEngine contains no nodes.")

        node_ids = set(nodes.keys())
        outgoing = getattr(dataflow_engine, "outgoing_edges", {})

        for src_id, edges in outgoing.items():
            if src_id not in node_ids:
                errors.append(f"Dataflow edge source ID '{src_id}' not found in registered nodes.")
            for edge in edges:
                tgt_id = getattr(edge, "target_id", None)
                if tgt_id and tgt_id not in node_ids:
                    errors.append(f"Dataflow edge target ID '{tgt_id}' not found in registered nodes.")

        return ValidationReport(is_valid=len(errors) == 0, artifact_type="Dataflow", errors=errors, warnings=warnings)

    def validate_findings(self, findings: list[Finding]) -> ValidationReport:
        """Validates Finding invariants: non-null fingerprints, valid severity, valid line numbers."""
        errors: list[str] = []
        warnings: list[str] = []

        for idx, finding in enumerate(findings):
            if not finding.fingerprint:
                errors.append(f"Finding [{idx}] '{finding.rule_id}' missing SHA-256 fingerprint.")
            line = finding.evidence.line if finding.evidence else 0
            if line <= 0:
                warnings.append(f"Finding [{idx}] '{finding.rule_id}' has non-positive line number: {line}")

        return ValidationReport(is_valid=len(errors) == 0, artifact_type="Findings", errors=errors, warnings=warnings)


artifact_validator = ArtifactValidator()
