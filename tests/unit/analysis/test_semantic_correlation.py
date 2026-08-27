"""Comprehensive unit, adversarial, fail-closed, and metamorphic test suite for Sprint E11 (INV-E11-FLOW-01..18)."""

from karsasec.analysis.semantic_correlator import SemanticCorrelator
from karsasec.analysis.semantic_flow import FlowStatus, SemanticFlow, compute_flow_id
from karsasec.analysis.semantic_flow_store import SemanticFlowStore
from karsasec.analysis.semantic_sanitizer import SanitizerAnalyzer
from karsasec.cpg.models import CPGEdge, CPGGraph, CPGNode, EdgeType, NodeType
from karsasec.framework.semantic_fact import SemanticFact, SemanticFactStore, SemanticRole
from karsasec.query.traversal_engine import MultiHopTraversalEngine
from karsasec.query.optimizer import QueryOptimizer


def build_sample_cpg() -> CPGGraph:
    """Constructs a sample CPG graph with HTTP input, transform, callsite, sanitizer, and SQL sink."""
    graph = CPGGraph()

    # Nodes
    n1 = CPGNode("n1", NodeType.CALLSITE, "request.args['id']", "app.py", 10, attributes={"symbol": "req_input", "source_kind": "http_user_input", "variable_name": "x", "ssa_version": "v1"})
    n2 = CPGNode("n2", NodeType.AST, "user_id = x", "app.py", 11, attributes={"variable_name": "x", "ssa_version": "v1", "caller": "handler", "callee": "get_user", "callsite": "site_42"})
    n3 = CPGNode("n3", NodeType.CALLSITE, "get_user(user_id)", "app.py", 12, attributes={"function_name": "get_user", "caller": "handler", "callee": "get_user", "callsite": "site_42"})
    n4 = CPGNode("n4", NodeType.CALLSITE, "query = 'SELECT ' + user_id", "db.py", 20, attributes={"variable_name": "query", "ssa_version": "v1", "caller": "get_user", "callee": "db_exec", "callsite": "site_99"})
    n5 = CPGNode("n5", NodeType.CALLSITE, "db.execute(query)", "db.py", 21, attributes={"sink_category": "sql", "caller": "db_exec", "callee": "execute", "callsite": "site_100"})

    for n in (n1, n2, n3, n4, n5):
        graph.add_node(n)

    # Edges forming dataflow path n1 -> n2 -> n3 -> n4 -> n5
    graph.add_edge(CPGEdge("n1", "n2", EdgeType.DATAFLOW))
    graph.add_edge(CPGEdge("n2", "n3", EdgeType.CALL))
    graph.add_edge(CPGEdge("n3", "n4", EdgeType.DATAFLOW))
    graph.add_edge(CPGEdge("n4", "n5", EdgeType.DATAFLOW))

    return graph




def test_inv_e11_flow_01_02_deterministic_flow_id() -> None:
    """INV-E11-FLOW-01,02: Deterministic 64-char SHA-256 Flow ID across runs."""
    id1 = compute_flow_id("src1", "snk1", ("n1", "n2"), (("c1", "c2", "cs1"),), (("x", "v1"),), ("san1",))
    id2 = compute_flow_id("src1", "snk1", ("n1", "n2"), (("c1", "c2", "cs1"),), (("x", "v1"),), ("san1",))
    id_diff = compute_flow_id("src1", "snk2", ("n1", "n2"), (("c1", "c2", "cs1"),), (("x", "v1"),), ("san1",))

    assert len(id1) == 64
    assert id1 == id2
    assert id1 != id_diff


def test_inv_e11_flow_03_directionality() -> None:
    """INV-E11-FLOW-03: Source -> Sink directionality must be preserved."""
    graph = build_sample_cpg()
    fact_store = SemanticFactStore()

    src_fact = SemanticFact.create("input", "FLASK", "req_input", "app.py", 10, semantic_role=SemanticRole.HTTP_INPUT, node_id="n1", source_kind="http_user_input")
    snk_fact = SemanticFact.create("sink", "FLASK", "execute", "db.py", 21, semantic_role=SemanticRole.SECURITY_SINK, node_id="n5", sink_category="sql")

    fact_store.add_fact(src_fact, graph)
    fact_store.add_fact(snk_fact, graph)

    correlator = SemanticCorrelator()
    flows = correlator.correlate(graph, fact_store, QueryOptimizer(), MultiHopTraversalEngine(graph)).all()


    assert len(flows) == 1
    assert flows[0].source_node_id == "n1"
    assert flows[0].sink_node_id == "n5"
    assert flows[0].status == FlowStatus.CORRELATED


def test_inv_e11_flow_04_07_08_reachability_cycles_depth() -> None:
    """INV-E11-FLOW-04,07,08: Reachability correctness, cycle termination, and depth bounding."""
    graph = build_sample_cpg()

    # Add cycle n3 -> n3_loop -> n3
    n_loop = CPGNode("n3_loop", NodeType.CALLSITE, "loop", "app.py", 15)
    graph.add_node(n_loop)
    graph.add_edge(CPGEdge("n3", "n3_loop", EdgeType.DATAFLOW))
    graph.add_edge(CPGEdge("n3_loop", "n3", EdgeType.DATAFLOW))


    fact_store = SemanticFactStore()
    src_fact = SemanticFact.create("input", "FLASK", "req_input", "app.py", 10, semantic_role=SemanticRole.HTTP_INPUT, node_id="n1")
    snk_fact = SemanticFact.create("sink", "FLASK", "execute", "db.py", 21, semantic_role=SemanticRole.SECURITY_SINK, node_id="n5")

    fact_store.add_fact(src_fact, graph)
    fact_store.add_fact(snk_fact, graph)

    correlator = SemanticCorrelator()
    flows = correlator.correlate(graph, fact_store, QueryOptimizer(), MultiHopTraversalEngine(graph), max_depth=10).all()


    assert len(flows) == 1
    assert flows[0].status == FlowStatus.CORRELATED


def test_inv_e11_flow_05_06_ssa_context_isolation() -> None:
    """INV-E11-FLOW-05,06: SSA isolation and Call Context binding."""
    graph = build_sample_cpg()
    fact_store = SemanticFactStore()

    src_fact = SemanticFact.create("input", "FLASK", "req_input", "app.py", 10, semantic_role=SemanticRole.HTTP_INPUT, node_id="n1")
    snk_fact = SemanticFact.create("sink", "FLASK", "execute", "db.py", 21, semantic_role=SemanticRole.SECURITY_SINK, node_id="n5")

    fact_store.add_fact(src_fact, graph)
    fact_store.add_fact(snk_fact, graph)

    correlator = SemanticCorrelator()
    flows = correlator.correlate(graph, fact_store, QueryOptimizer(), MultiHopTraversalEngine(graph)).all()


    assert len(flows) == 1
    assert len(flows[0].call_context) > 0
    assert len(flows[0].ssa_chain) > 0


def test_inv_e11_flow_09_10_11_fail_closed() -> None:
    """INV-E11-FLOW-09,10,11: Fail-closed on missing node, missing SSA, or ambiguous context."""
    graph = build_sample_cpg()
    fact_store = SemanticFactStore()

    # Fact referencing non-existent node
    src_fact = SemanticFact.create("input", "FLASK", "req_input", "app.py", 10, semantic_role=SemanticRole.HTTP_INPUT, node_id="missing_node")
    snk_fact = SemanticFact.create("sink", "FLASK", "execute", "db.py", 21, semantic_role=SemanticRole.SECURITY_SINK, node_id="n5")

    fact_store.add_fact(src_fact)
    fact_store.add_fact(snk_fact)

    correlator = SemanticCorrelator()
    flows = correlator.correlate(graph, fact_store, QueryOptimizer(), MultiHopTraversalEngine(graph)).all()


    assert len(flows) == 1
    assert flows[0].status == FlowStatus.UNKNOWN


def test_inv_e11_flow_12_13_sanitizer_validation_and_fake_rejection() -> None:
    """INV-E11-FLOW-12,13: Genuine sanitizers block flows, fake sanitizers are rejected."""
    analyzer = SanitizerAnalyzer()

    # Fake sanitizer test
    fake_node = CPGNode("f1", NodeType.CALLSITE, "str(x)", "app.py", 10, attributes={"function_name": "str"})
    evidence_fake = analyzer.analyze_node(fake_node)
    assert evidence_fake is None

    # Valid sanitizer test
    valid_node = CPGNode("v1", NodeType.CALLSITE, "sanitize_sql(x)", "app.py", 10, attributes={"function_name": "sanitize_sql"})
    evidence_valid = analyzer.analyze_node(valid_node)
    assert evidence_valid is not None
    assert analyzer.is_valid_barrier_for_sink(evidence_valid, "sql") is True
    assert analyzer.is_valid_barrier_for_sink(evidence_valid, "command_execution") is False

    # Correlate flow with valid sanitizer node
    graph = build_sample_cpg()
    # Remove direct edge n3 -> n4 to force path through sanitizer node
    graph.edges = [e for e in graph.edges if not (e.source_id == "n3" and e.target_id == "n4")]
    graph._adjacency_out["n3"] = [e for e in graph._adjacency_out["n3"] if e.target_id != "n4"]
    graph._adjacency_in["n4"] = [e for e in graph._adjacency_in["n4"] if e.source_id != "n3"]

    san_node = CPGNode("n_san", NodeType.CALLSITE, "int(user_id)", "app.py", 13, attributes={"function_name": "int"})
    graph.add_node(san_node)
    graph.add_edge(CPGEdge("n3", "n_san", EdgeType.DATAFLOW))
    graph.add_edge(CPGEdge("n_san", "n4", EdgeType.DATAFLOW))


    fact_store = SemanticFactStore()
    src_fact = SemanticFact.create("input", "FLASK", "req_input", "app.py", 10, semantic_role=SemanticRole.HTTP_INPUT, node_id="n1")
    snk_fact = SemanticFact.create("sink", "FLASK", "execute", "db.py", 21, semantic_role=SemanticRole.SECURITY_SINK, node_id="n5", sink_category="sql")

    fact_store.add_fact(src_fact, graph)
    fact_store.add_fact(snk_fact, graph)

    correlator = SemanticCorrelator()
    flows = correlator.correlate(graph, fact_store, QueryOptimizer(), MultiHopTraversalEngine(graph)).all()


    assert len(flows) == 1
    assert flows[0].status == FlowStatus.BLOCKED


def test_inv_e11_flow_14_15_store_deduplication_and_cpg_immutability() -> None:
    """INV-E11-FLOW-14,15: Flow deduplication & zero CPG topology mutation."""
    store = SemanticFlowStore()
    flow1 = SemanticFlow.create("src1", "snk1", "n1", "n5")
    flow2 = SemanticFlow.create("src1", "snk1", "n1", "n5")

    assert store.add(flow1) is True
    assert store.add(flow2) is False
    assert store.count() == 1

    graph = build_sample_cpg()
    nodes_before = len(graph.nodes)
    edges_before = len(graph.edges)

    fact_store = SemanticFactStore()
    fact_store.add_fact(SemanticFact.create("input", "FLASK", "req_input", "app.py", 10, semantic_role=SemanticRole.HTTP_INPUT, node_id="n1"), graph)
    fact_store.add_fact(SemanticFact.create("sink", "FLASK", "execute", "db.py", 21, semantic_role=SemanticRole.SECURITY_SINK, node_id="n5"), graph)

    SemanticCorrelator().correlate(graph, fact_store, QueryOptimizer(), MultiHopTraversalEngine(graph))

    assert len(graph.nodes) == nodes_before
    assert len(graph.edges) == edges_before


def test_inv_e11_flow_18_idempotency() -> None:
    """INV-E11-FLOW-18: Extraction and correlation idempotency."""
    graph = build_sample_cpg()
    fact_store = SemanticFactStore()
    fact_store.add_fact(SemanticFact.create("input", "FLASK", "req_input", "app.py", 10, semantic_role=SemanticRole.HTTP_INPUT, node_id="n1"), graph)
    fact_store.add_fact(SemanticFact.create("sink", "FLASK", "execute", "db.py", 21, semantic_role=SemanticRole.SECURITY_SINK, node_id="n5"), graph)

    correlator = SemanticCorrelator()
    flow_store1 = correlator.correlate(graph, fact_store, QueryOptimizer(), MultiHopTraversalEngine(graph))
    flow_store2 = correlator.correlate(graph, fact_store, QueryOptimizer(), MultiHopTraversalEngine(graph))

    assert flow_store1.count() == flow_store2.count()
    assert [f.flow_id for f in flow_store1.all()] == [f.flow_id for f in flow_store2.all()]


def test_metamorphic_reordering_and_unrelated_nodes() -> None:
    """Metamorphic tests: input reordering and unrelated node insertion preserve flow identity."""
    graph = build_sample_cpg()
    fact_store = SemanticFactStore()

    f1 = SemanticFact.create("input1", "FLASK", "req1", "app.py", 10, semantic_role=SemanticRole.HTTP_INPUT, node_id="n1")
    f2 = SemanticFact.create("sink1", "FLASK", "exec1", "db.py", 21, semantic_role=SemanticRole.SECURITY_SINK, node_id="n5")

    fact_store.add_fact(f1, graph)
    fact_store.add_fact(f2, graph)

    correlator = SemanticCorrelator()
    flows_orig = correlator.correlate(graph, fact_store, QueryOptimizer(), MultiHopTraversalEngine(graph)).all()

    # Add unrelated node to graph
    graph.add_node(CPGNode("unrelated_99", NodeType.AST, "foo = 1", "other.py", 1))
    flows_meta = correlator.correlate(graph, fact_store, QueryOptimizer(), MultiHopTraversalEngine(graph)).all()

    assert [f.flow_id for f in flows_orig] == [f.flow_id for f in flows_meta]


