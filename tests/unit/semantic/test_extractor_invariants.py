"""Invariants Test Suite for Sprint E10 Framework Semantic Extractors (INV-E10-SEM-01..17)."""

import os
import subprocess
import sys
from karsasec.cpg.index import CPGIndex
from karsasec.cpg.models import CPGGraph, CPGNode, NodeType
from karsasec.framework.detector import FrameworkDetector
from karsasec.framework.extractors.base import ExtractorContext
from karsasec.framework.extractors.endpoint_extractor import HTTPEndpointExtractor
from karsasec.framework.extractors.input_extractor import HTTPInputSourceExtractor
from karsasec.framework.extractors.registry import ExtractorRegistry
from karsasec.framework.semantic_fact import (
    SemanticFact,
    SemanticFactStore,
)



def test_inv_e10_sem_01_deterministic_fact_id() -> None:
    """INV-E10-SEM-01: Fact IDs must be 100% deterministic SHA-256 digests."""
    f1 = SemanticFact.create("endpoint", "FLASK", "index", "app.py", 10, metadata={"path": "/"})
    f2 = SemanticFact.create("endpoint", "FLASK", "index", "app.py", 10, metadata={"path": "/"})
    assert f1.fact_id == f2.fact_id
    assert len(f1.fact_id) == 64


def test_inv_e10_sem_02_pythonhashseed_independence() -> None:
    """INV-E10-SEM-02: Fact IDs must be hashseed independent."""
    code = """
from karsasec.framework.semantic_fact import compute_fact_id
print(compute_fact_id("FASTAPI", "endpoint", "main.py", 15, "get_users", {"b": 2, "a": 1}))
"""
    seeds = ["0", "9999", "12345"]
    results = set()
    for s in seeds:
        env = dict(os.environ, PYTHONHASHSEED=s)
        out = subprocess.check_output([sys.executable, "-c", code], env=env, text=True).strip()
        results.add(out)

    assert len(results) == 1, f"Hash seed divergence: {results}"


def test_inv_e10_sem_03_15_idempotency_and_no_duplication() -> None:
    """INV-E10-SEM-03 & 15: Extraction over same graph must be idempotent and non-duplicating."""
    store = SemanticFactStore()
    fact = SemanticFact.create("source", "EXPRESS", "req.query", "server.js", 5)

    assert store.add_fact(fact) is True
    assert store.add_fact(fact) is False  # Second attempt rejected
    assert len(store.all_facts()) == 1


def test_inv_e10_sem_04_07_unknown_produces_no_fabricated_facts() -> None:
    """INV-E10-SEM-04 & 07: Ambiguous/UNKNOWN framework identity produces NO facts and NO security verdict."""
    detector = FrameworkDetector()
    ast_nodes = [
        type("Node", (), {"node_type": "FUNCTION", "name": "foo", "attributes": {}})(),
    ]
    detection = detector.detect_from_ast(ast_nodes, "unknown.py")
    assert detection.framework == "UNKNOWN"

    ctx = ExtractorContext(framework=detection.framework, ast_nodes=ast_nodes)
    ext = HTTPEndpointExtractor()
    res = ext.extract(ctx)
    assert len(res.statistics) == 0


def test_inv_e10_sem_08_error_isolation() -> None:
    """INV-E10-SEM-08: An exception in one extractor leaves remaining extractors functional."""
    registry = ExtractorRegistry()

    class BrokenExtractor(HTTPEndpointExtractor):
        @property
        def name(self) -> str:
            return "BrokenExtractor"

        @property
        def priority(self) -> int:
            return 5

        def extract(self, ctx: ExtractorContext):
            raise RuntimeError("Fatal extractor failure")

    registry.register(BrokenExtractor())
    registry.register(HTTPInputSourceExtractor())

    ast_nodes = [
        type("Node", (), {"node_type": "EXPRESSION", "name": "req.query", "attributes": {}, "id": "n1", "file_path": "app.py", "line_number": 10})(),
    ]
    ctx = ExtractorContext(framework="EXPRESS", ast_nodes=ast_nodes)

    res, diags = registry.extract_all(ctx)
    assert len(diags) == 1
    assert diags[0]["extractor_name"] == "BrokenExtractor"
    assert len(res.statistics) == 1  # Input extractor still succeeded!


def test_inv_e10_sem_13_node_id_validity() -> None:
    """INV-E10-SEM-13: Node-bound facts MUST reference an existing CPGNode."""
    store = SemanticFactStore()
    graph = CPGGraph()
    graph.nodes["n1"] = CPGNode(id="n1", node_type=NodeType.CALLSITE, label="CALL", file_path="app.py", line_number=10)

    f_valid = SemanticFact.create("sink", "FLASK", "exec", "app.py", 10, node_id="n1")
    f_invalid = SemanticFact.create("sink", "FLASK", "exec", "app.py", 10, node_id="ghost_node")

    assert store.add_fact(f_valid, graph=graph) is True
    assert store.add_fact(f_invalid, graph=graph) is False


def test_inv_e10_sem_14_topology_preservation() -> None:
    """INV-E10-SEM-14: Semantic extraction MUST NOT mutate CPG topology (node or edge count)."""
    graph = CPGGraph()
    graph.nodes["n1"] = CPGNode(id="n1", node_type=NodeType.CALLSITE, label="CALL", file_path="app.py", line_number=10)

    initial_nodes = len(graph.nodes)
    initial_edges = len(graph.edges)

    store = SemanticFactStore()
    fact = SemanticFact.create("sink", "FLASK", "exec", "app.py", 10, node_id="n1", sink_category="sql")
    store.add_fact(fact, graph=graph)
    store.attach_to_cpg(graph)

    assert len(graph.nodes) == initial_nodes
    assert len(graph.edges) == initial_edges


def test_inv_e10_sem_16_unrelated_code_addition_stability() -> None:
    """INV-E10-SEM-16: Adding unrelated code does NOT alter existing SemanticFact IDs."""
    f1 = SemanticFact.create("endpoint", "FLASK", "get_user", "users.py", 20, metadata={"path": "/users"})

    # Unrelated code added in another file
    f_unrelated = SemanticFact.create("endpoint", "FLASK", "get_product", "products.py", 10, metadata={"path": "/products"})

    assert f1.fact_id != f_unrelated.fact_id
    # Recomputing f1 produces exact same fact_id
    f1_recomputed = SemanticFact.create("endpoint", "FLASK", "get_user", "users.py", 20, metadata={"path": "/users"})
    assert f1.fact_id == f1_recomputed.fact_id


def test_inv_e10_sem_17_cpg_index_equivalence() -> None:
    """INV-E10-SEM-17: CPGIndex results after attachment match authoritative CPG graph scan."""
    graph = CPGGraph()
    graph.nodes["n1"] = CPGNode(id="n1", node_type=NodeType.CALLSITE, label="CALL", file_path="app.py", line_number=10)
    graph.nodes["n2"] = CPGNode(id="n2", node_type=NodeType.CALLSITE, label="CALL", file_path="app.py", line_number=20)

    store = SemanticFactStore()
    fact = SemanticFact.create("sink", "FLASK", "exec", "app.py", 10, node_id="n1", sink_category="sql")
    store.add_fact(fact, graph=graph)
    store.attach_to_cpg(graph)

    index = CPGIndex(graph)
    indexed_sinks = index.get_by_sink_category("sql")
    graph_sinks = [n for n in graph.nodes.values() if n.attributes.get("sink_category") == "sql"]

    assert indexed_sinks == graph_sinks
    assert len(indexed_sinks) == 1
    assert indexed_sinks[0].id == "n1"
