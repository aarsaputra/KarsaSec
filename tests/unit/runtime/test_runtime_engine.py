"""Unit test suite for karsasec/runtime/ execution planner, capability graph, and stable finding fingerprinting."""

from pathlib import Path

from karsasec.core.capability_graph import capability_graph
from karsasec.core.finding.model import compute_stable_finding_fingerprint
from karsasec.rules.enums import AnalysisCapability
from karsasec.runtime.planner import CapabilityDependencyPlanner, ExecutionPlanner


def test_capability_dependency_planner_topological_sort() -> None:
    """Verify CapabilityDependencyPlanner correctly resolves prerequisite dependencies in order."""
    planner = CapabilityDependencyPlanner()

    # Requesting DATAFLOW should pull AST, HIERARCHY, SEMANTIC, CALLGRAPH, DATAFLOW
    order = planner.resolve_execution_order({AnalysisCapability.DATAFLOW})

    assert AnalysisCapability.AST in order
    assert AnalysisCapability.SEMANTIC in order
    assert AnalysisCapability.CALLGRAPH in order
    assert AnalysisCapability.DATAFLOW in order

    # Verify topological order constraints
    ast_idx = order.index(AnalysisCapability.AST)
    sem_idx = order.index(AnalysisCapability.SEMANTIC)
    df_idx = order.index(AnalysisCapability.DATAFLOW)

    assert ast_idx < sem_idx < df_idx


def test_capability_graph_prerequisites() -> None:
    """Verify CapabilityGraph direct and transitive prerequisites query API."""
    prereqs = capability_graph.get_all_transitive_prerequisites(AnalysisCapability.DATAFLOW)
    assert AnalysisCapability.AST in prereqs
    assert AnalysisCapability.SEMANTIC in prereqs
    assert AnalysisCapability.CALLGRAPH in prereqs


def test_stable_finding_fingerprint_determinism() -> None:
    """Verify compute_stable_finding_fingerprint generates deterministic hashes regardless of OS slashes."""
    path1 = Path("src/controllers/user.py")
    path2 = Path("src\\controllers\\user.py")

    hash1 = compute_stable_finding_fingerprint("KS-PY-0001", path1, "eval(user_input)", 42, "CWE-95")
    hash2 = compute_stable_finding_fingerprint("KS-PY-0001", path2, "eval(user_input)", 42, "CWE-95")

    assert hash1 == hash2
    assert len(hash1) == 32
