"""Phase 2 — INV-D4-CAUSALITY-01 Causal Evidence Gate Tests.

Verifies that D4 correlation engine:
1. Does NOT create edges when only contextual correlation signals exist (same correlation_id)
2. Creates edges ONLY when typed causal evidence exists
3. Assigns correct confidence levels based on causal evidence type
"""

from karsasec.analysis.correlation.engine import CrossBatchCorrelationEngine
from karsasec.analysis.correlation.models import (
    CausalEvidenceType,
    CorrelationConfidence,
    CrossBatchNode,
    EdgeRelation,
    EvidenceSource,
    IdentityType,
    SecurityProperty,
)


def _make_node(
    node_id: str,
    *,
    correlation_id: str = "SHARED_CORR",
    source_batch: EvidenceSource = EvidenceSource.C13,
    actor: str = "user_a",
    resource: str = "res_a",
    privilege: str = "LOW",
    identity_type: IdentityType = IdentityType.END_USER,
    causal_evidence: tuple[CausalEvidenceType, ...] = (),
) -> CrossBatchNode:
    return CrossBatchNode(
        node_id=node_id,
        source_batch=source_batch,
        source_type="FINDING",
        source_id=f"SRC_{node_id}",
        correlation_id=correlation_id,
        actor_identity=actor,
        identity_type=identity_type,
        tenant_id="tenant_a",
        privilege_level=privilege,
        capability="ACCESS",
        action="READ",
        resource=resource,
        security_property=SecurityProperty.UNKNOWN,
        causal_evidence=causal_evidence,
    )


# === CORE INVARIANT: No causal evidence → No edge ===


def test_500_nodes_same_corr_id_no_causal_evidence_produces_zero_edges() -> None:
    """500 nodes with identical correlation_id but no causal evidence → 0 edges."""
    engine = CrossBatchCorrelationEngine()
    nodes = [_make_node(f"N_{i:04d}") for i in range(500)]
    edges = engine.build_correlation_graph(nodes)
    assert len(edges) == 0, f"Expected 0 edges, got {len(edges)}. INV-D4-CAUSALITY-01 violated!"


def test_same_actor_same_resource_same_timestamp_no_causal_evidence_zero_edges() -> None:
    """Contextual correlation signals (same actor, resource, timestamp) are NOT causal evidence."""
    engine = CrossBatchCorrelationEngine()
    nodes = [
        _make_node("A", actor="admin", resource="db_main"),
        _make_node("B", actor="admin", resource="db_main"),
    ]
    edges = engine.build_correlation_graph(nodes)
    assert len(edges) == 0


def test_different_corr_ids_zero_edges() -> None:
    """Nodes with different correlation IDs never correlate."""
    engine = CrossBatchCorrelationEngine()
    nodes = [_make_node(f"N_{i}", correlation_id=f"CORR_{i}") for i in range(50)]
    edges = engine.build_correlation_graph(nodes)
    assert len(edges) == 0


# === Typed Causal Evidence → Edge creation ===


def test_data_dependency_creates_high_confidence_causal_edge() -> None:
    """DATA_DEPENDENCY typed causal evidence creates HIGH confidence CAUSAL edge."""
    engine = CrossBatchCorrelationEngine()
    nodes = [
        _make_node("A", causal_evidence=(CausalEvidenceType.DATA_DEPENDENCY,)),
        _make_node("B"),
    ]
    edges = engine.build_correlation_graph(nodes)
    assert len(edges) == 1
    assert edges[0].relation == EdgeRelation.CAUSAL
    assert edges[0].confidence == CorrelationConfidence.HIGH


def test_control_dependency_creates_high_confidence_causal_edge() -> None:
    """CONTROL_DEPENDENCY typed causal evidence creates HIGH confidence CAUSAL edge."""
    engine = CrossBatchCorrelationEngine()
    nodes = [
        _make_node("A", causal_evidence=(CausalEvidenceType.CONTROL_DEPENDENCY,)),
        _make_node("B"),
    ]
    edges = engine.build_correlation_graph(nodes)
    assert len(edges) == 1
    assert edges[0].relation == EdgeRelation.CAUSAL
    assert edges[0].confidence == CorrelationConfidence.HIGH


def test_explicit_provenance_creates_high_confidence_edge() -> None:
    """EXPLICIT_PROVENANCE creates HIGH confidence CAUSAL edge."""
    engine = CrossBatchCorrelationEngine()
    nodes = [
        _make_node("A", causal_evidence=(CausalEvidenceType.EXPLICIT_PROVENANCE,)),
        _make_node("B"),
    ]
    edges = engine.build_correlation_graph(nodes)
    assert len(edges) == 1
    assert edges[0].confidence == CorrelationConfidence.HIGH


def test_privilege_transition_creates_medium_confidence_edge() -> None:
    """PRIVILEGE_TRANSITION creates MEDIUM confidence PRIVILEGE edge."""
    engine = CrossBatchCorrelationEngine()
    nodes = [
        _make_node("A", causal_evidence=(CausalEvidenceType.PRIVILEGE_TRANSITION,)),
        _make_node("B"),
    ]
    edges = engine.build_correlation_graph(nodes)
    assert len(edges) == 1
    assert edges[0].relation == EdgeRelation.PRIVILEGE
    assert edges[0].confidence == CorrelationConfidence.MEDIUM


def test_explicit_delegation_creates_medium_confidence_edge() -> None:
    """EXPLICIT_DELEGATION creates MEDIUM confidence DELEGATION edge."""
    engine = CrossBatchCorrelationEngine()
    nodes = [
        _make_node("A", causal_evidence=(CausalEvidenceType.EXPLICIT_DELEGATION,)),
        _make_node("B"),
    ]
    edges = engine.build_correlation_graph(nodes)
    assert len(edges) == 1
    assert edges[0].relation == EdgeRelation.DELEGATION
    assert edges[0].confidence == CorrelationConfidence.MEDIUM


# === Implicit causal structure detection ===


def test_monotonic_privilege_escalation_is_implicit_causal() -> None:
    """Privilege escalation LOW→HIGH is an implicit PRIVILEGE_TRANSITION."""
    engine = CrossBatchCorrelationEngine()
    nodes = [
        _make_node("A", privilege="LOW"),
        _make_node("B", privilege="HIGH"),
    ]
    edges = engine.build_correlation_graph(nodes)
    assert len(edges) == 1
    assert edges[0].relation == EdgeRelation.PRIVILEGE


def test_delegated_identity_is_implicit_causal() -> None:
    """DELEGATED_IDENTITY is an implicit EXPLICIT_DELEGATION."""
    engine = CrossBatchCorrelationEngine()
    nodes = [
        _make_node("A"),
        _make_node("B", identity_type=IdentityType.DELEGATED_IDENTITY),
    ]
    edges = engine.build_correlation_graph(nodes)
    assert len(edges) == 1
    assert edges[0].relation == EdgeRelation.DELEGATION


def test_same_privilege_no_escalation_no_edge() -> None:
    """Same privilege level with no other causal evidence → no edge."""
    engine = CrossBatchCorrelationEngine()
    nodes = [
        _make_node("A", privilege="HIGH"),
        _make_node("B", privilege="HIGH"),
    ]
    edges = engine.build_correlation_graph(nodes)
    assert len(edges) == 0


# === Mixed scenario ===


def test_500_nodes_with_causal_evidence_produces_499_edges() -> None:
    """500 nodes with same correlation_id and DATA_DEPENDENCY → 499 edges."""
    engine = CrossBatchCorrelationEngine()
    nodes = [
        _make_node(
            f"N_{i:04d}",
            causal_evidence=(CausalEvidenceType.DATA_DEPENDENCY,),
        )
        for i in range(500)
    ]
    edges = engine.build_correlation_graph(nodes)
    assert len(edges) == 499
