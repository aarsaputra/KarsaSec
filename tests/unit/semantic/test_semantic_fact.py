"""Unit tests for SemanticFact, deterministic identity, and SemanticFactStore."""

import os
import subprocess
import sys
from karsasec.cpg.models import CPGGraph, CPGNode, NodeType
from karsasec.framework.semantic_fact import (
    ConfidenceLevel,
    SemanticFact,
    SemanticFactStore,
    SemanticRole,
    compute_fact_id,
)


def test_compute_fact_id_determinism() -> None:
    """Fact ID calculation must be 64-character SHA256 hex and 100% deterministic."""
    fid1 = compute_fact_id("FLASK", "endpoint", "app.py", 10, "get_user", {"method": "GET"})
    fid2 = compute_fact_id("FLASK", "endpoint", "app.py", 10, "get_user", {"method": "GET"})
    assert len(fid1) == 64
    assert fid1 == fid2


def test_compute_fact_id_dictionary_key_ordering() -> None:
    """Dictionary key ordering in metadata must not alter fact ID."""
    meta1 = {"method": "GET", "path": "/users", "auth": True}
    meta2 = {"auth": True, "method": "GET", "path": "/users"}
    fid1 = compute_fact_id("EXPRESS", "endpoint", "server.js", 15, "router", meta1)
    fid2 = compute_fact_id("EXPRESS", "endpoint", "server.js", 15, "router", meta2)
    assert fid1 == fid2


def test_semantic_fact_create_and_serialization() -> None:
    """SemanticFact factory creation, dictionary serialization, and deserialization."""
    fact = SemanticFact.create(
        kind="endpoint",
        framework="FLASK",
        symbol="index",
        file="routes.py",
        line=20,
        semantic_role=SemanticRole.HTTP_ENDPOINT,
        node_id="n1",
        metadata={"path": "/"},
        confidence=0.95,
        confidence_level=ConfidenceLevel.HIGH,
    )

    assert len(fact.fact_id) == 64
    d = fact.to_dict()
    restored = SemanticFact.from_dict(d)
    assert restored.fact_id == fact.fact_id
    assert restored.framework == "FLASK"
    assert restored.semantic_role == SemanticRole.HTTP_ENDPOINT.value


def test_semantic_fact_store_deduplication() -> None:
    """SemanticFactStore must deduplicate identical facts (INV-E10-SEM-15)."""
    store = SemanticFactStore()
    fact1 = SemanticFact.create("sink", "DJANGO", "raw_query", "db.py", 42, metadata={"db": "postgres"})
    fact2 = SemanticFact.create("sink", "DJANGO", "raw_query", "db.py", 42, metadata={"db": "postgres"})

    assert store.add_fact(fact1) is True
    assert store.add_fact(fact2) is False  # Deduplicated
    assert len(store.all_facts()) == 1


def test_semantic_fact_store_cpg_node_validation() -> None:
    """SemanticFactStore must reject facts bound to non-existent CPG nodes (INV-E10-SEM-13)."""
    store = SemanticFactStore()
    graph = CPGGraph()
    graph.nodes["n100"] = CPGNode(id="n100", node_type=NodeType.CALLSITE, label="CALL", language="Python", file_path="app.py", line_number=1)

    fact_valid = SemanticFact.create("source", "FLASK", "arg", "app.py", 1, node_id="n100")
    fact_invalid = SemanticFact.create("source", "FLASK", "arg", "app.py", 2, node_id="n999")

    assert store.add_fact(fact_valid, graph=graph) is True
    assert store.add_fact(fact_invalid, graph=graph) is False


def test_semantic_fact_store_attach_to_cpg() -> None:
    """SemanticFactStore attach_to_cpg attaches facts to CPGNode attributes."""
    store = SemanticFactStore()
    graph = CPGGraph()
    graph.nodes["n1"] = CPGNode(id="n1", node_type=NodeType.CALLSITE, label="CALL", language="Python", file_path="app.py", line_number=5)

    fact = SemanticFact.create(
        kind="sink",
        framework="FLASK",
        symbol="execute",
        file="app.py",
        line=5,
        node_id="n1",
        semantic_role=SemanticRole.SECURITY_SINK,
        sink_category="sql",
    )
    store.add_fact(fact, graph=graph)
    updated = store.attach_to_cpg(graph)

    assert updated == 1
    assert "semantic_facts" in graph.nodes["n1"].attributes
    assert graph.nodes["n1"].attributes["sink_category"] == "sql"


def test_fact_id_python_hash_seed_independence() -> None:
    """Fact ID calculation must remain identical across different PYTHONHASHSEED values."""
    code = """
import sys
from karsasec.framework.semantic_fact import compute_fact_id

fid = compute_fact_id("FASTAPI", "endpoint", "main.py", 12, "read_root", {"method": "GET"})
print(fid)
"""
    seeds = ["0", "42", "1337", "random"]
    results = set()
    for seed in seeds:
        env = dict(os.environ, PYTHONHASHSEED=seed)
        res = subprocess.check_output([sys.executable, "-c", code], env=env, text=True).strip()
        results.add(res)

    assert len(results) == 1, f"PYTHONHASHSEED caused non-deterministic fact_ids: {results}"
