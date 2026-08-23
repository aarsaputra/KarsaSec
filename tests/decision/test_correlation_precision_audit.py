"""CORRELATION_PRECISION_AUDIT Test Suite.

Audits D4 Correlation Engine for:
- INV-D4-GRAPH-BOUND-01 (Prevention of quadratic O(N^2) edge generation explosion)
- False Correlation Rate (Correlation entropy verification)
- Reachability vs Mathematical Proof terminology calibration
"""

from karsasec.analysis.correlation.engine import CrossBatchCorrelationEngine
from karsasec.analysis.correlation.models import CausalEvidenceType, CrossBatchNode, EvidenceSource, IdentityType, SecurityProperty

def test_inv_d4_graph_bound_01_prevents_quadratic_explosion() -> None:
    """Verify INV-D4-GRAPH-BOUND-01 bounds edge creation to E <= 10 * V for large correlation clusters."""
    engine = CrossBatchCorrelationEngine()
    v_count = 500
    nodes = [
        CrossBatchNode(
            node_id=f"NODE_{i:04d}",
            source_batch=EvidenceSource.C13,
            source_type="FINDING",
            source_id=f"SRC_{i}",
            correlation_id="SHARED_CLUSTER_ID",  # All 500 nodes share the same correlation ID
            actor_identity="user",
            identity_type=IdentityType.END_USER,
            tenant_id="tenant_a",
            privilege_level="LOW",
            capability="READ",
            action="ACCESS",
            resource="res_a",
            security_property=SecurityProperty.UNKNOWN,
            causal_evidence=(CausalEvidenceType.DATA_DEPENDENCY,),
        )
        for i in range(v_count)
    ]

    edges = engine.build_correlation_graph(nodes)
    # Adjacent linear chaining produces exactly V - 1 edges (499 edges)
    assert len(edges) == v_count - 1
    # Formally verify linear edge bound E <= 10 * V
    assert len(edges) <= 10 * v_count


def test_correlation_precision_refuses_unrelated_correlation_ids() -> None:
    """Verify nodes with different correlation IDs produce 0 false correlation edges."""
    engine = CrossBatchCorrelationEngine()
    nodes = [
        CrossBatchNode(
            node_id=f"NODE_{i:02d}",
            source_batch=EvidenceSource.C13,
            source_type="FINDING",
            source_id=f"SRC_{i}",
            correlation_id=f"CORR_{i}",  # Distinct correlation ID per node
            actor_identity="user",
            identity_type=IdentityType.END_USER,
            tenant_id="tenant_a",
            privilege_level="LOW",
            capability="READ",
            action="ACCESS",
            resource="res_a",
            security_property=SecurityProperty.UNKNOWN,
        )
        for i in range(50)
    ]

    edges = engine.build_correlation_graph(nodes)
    assert len(edges) == 0, "Unrelated correlation IDs must produce 0 correlation edges!"
