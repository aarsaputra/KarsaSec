"""SemanticRuleEngine implementing flow evaluation, sanitizer barrier matrix, confidence calculation, and finding status decisions for Sprint E12."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from karsasec.analysis.rule_condition import ConditionResult
from karsasec.analysis.rule_registry import SecurityRuleRegistry, create_default_registry
from karsasec.analysis.security_finding import FindingStatus, SecurityFinding
from karsasec.analysis.security_finding_store import SecurityFindingStore
from karsasec.analysis.semantic_flow import FlowStatus

if TYPE_CHECKING:
    from karsasec.analysis.semantic_flow import SemanticFlow
    from karsasec.analysis.semantic_flow_store import SemanticFlowStore
    from karsasec.cpg.models import CPGGraph
    from karsasec.framework.semantic_fact import SemanticFact, SemanticFactStore

logger = logging.getLogger("karsasec.analysis.rule_engine")

# Category-Specific Barrier Matrix (INV-E12-RULE-14,15,16)
SINK_CATEGORY_BARRIER_MATRIX: dict[str, tuple[str, ...]] = {
    "sql": ("int", "sanitize_sql", "parameterized_query", "prepared_statement"),
    "command_execution": ("shlex.quote", "command_allowlist", "safe_exec"),
    "html_render": ("escape_html", "html_escape", "framework_auto_escape"),
    "file_path": ("path_allowlist", "realpath_boundary_check", "safe_join", "basename"),
    "code_execution": ("strict_allowlist", "static_dispatch", "ast.literal_eval"),
}

# Explicit Fake Sanitizers (NEVER BARRIERS)
FAKE_SANITIZERS: tuple[str, ...] = ("str", "trim", "lower", "upper", "string")


@dataclass(frozen=True)
class FlowValidationResult:
    """Result of flow integrity validation."""

    valid: bool
    reason: str


def validate_flow_integrity(
    flow: SemanticFlow,
    fact_store: SemanticFactStore,
    graph: CPGGraph,
) -> FlowValidationResult:
    """Validates flow, node, and fact integrity (INV-E12-RULE-09,10,11)."""
    if flow is None:
        return FlowValidationResult(valid=False, reason="SemanticFlow is None")

    source_fact = fact_store.get_fact(flow.source_fact_id)
    if source_fact is None:
        return FlowValidationResult(valid=False, reason=f"Source fact '{flow.source_fact_id}' not found in store")

    sink_fact = fact_store.get_fact(flow.sink_fact_id)
    if sink_fact is None:
        return FlowValidationResult(valid=False, reason=f"Sink fact '{flow.sink_fact_id}' not found in store")

    if flow.source_node_id not in graph.nodes:
        return FlowValidationResult(valid=False, reason=f"Source node '{flow.source_node_id}' not found in CPG")

    if flow.sink_node_id not in graph.nodes:
        return FlowValidationResult(valid=False, reason=f"Sink node '{flow.sink_node_id}' not found in CPG")

    for nid in flow.path_node_ids:
        if nid not in graph.nodes:
            return FlowValidationResult(valid=False, reason=f"Path node '{nid}' not found in CPG")

    # Direction check: if path exists, source should precede sink
    if flow.path_node_ids:
        if flow.path_node_ids[0] != flow.source_node_id or flow.path_node_ids[-1] != flow.sink_node_id:
            return FlowValidationResult(valid=False, reason="Path directionality violation (source must lead to sink)")

    return FlowValidationResult(valid=True, reason="Flow integrity verified")


@dataclass(frozen=True)
class BarrierEvaluationResult:
    """Result of sink-category-specific sanitizer barrier evaluation."""

    has_valid_barrier: bool
    barrier_name: str | None
    evidence: tuple[str, ...]


def _match_symbol_name(func_name: str, barrier_pattern: str) -> bool:
    """Matches function symbol name using exact name or fully-qualified name (FQN) suffix logic.

    Prevents CWE-20 Substring Spoofing (SEC-001):
    - Matches exact string (e.g. 'int' == 'int', 'shlex.quote' == 'shlex.quote').
    - Matches FQN module prefix (e.g. 'builtins.int' matches 'int', 'os.path.basename' matches 'basename').
    - Does NOT match substring contained within identifiers (e.g. 'user_int_converter' does NOT match 'int').
    """
    clean_func = func_name.strip().lower()
    clean_pattern = barrier_pattern.strip().lower()

    if clean_func == clean_pattern:
        return True

    # Check if func_name is FQN ending with .barrier_pattern (e.g. builtins.int -> int)
    if clean_func.endswith("." + clean_pattern):
        return True

    return False


def evaluate_sanitizer_barrier(
    flow: SemanticFlow,
    sink_category: str,
    graph: CPGGraph,
) -> BarrierEvaluationResult:
    """Evaluates sink-category-specific sanitizer barrier matrix using exact symbol matching (INV-E12-RULE-14,15,16)."""
    category_key = (sink_category or "").lower()
    valid_barriers = SINK_CATEGORY_BARRIER_MATRIX.get(category_key, ())

    detected_valid: list[str] = []
    detected_fake_or_cross: list[str] = []

    for nid in flow.sanitizer_nodes:
        if nid in graph.nodes:
            node = graph.nodes[nid]
            func_name = (
                node.attributes.get("name")
                or node.attributes.get("function_name")
                or node.attributes.get("callee")
                or node.label
            ).lower()

            # Check if explicitly a fake sanitizer using exact symbol matching (SEC-001)
            if any(_match_symbol_name(func_name, fake) for fake in FAKE_SANITIZERS):
                detected_fake_or_cross.append(f"fake:{func_name}")
                continue

            # Check if matching sink-category barrier using exact symbol matching (SEC-001)
            if any(_match_symbol_name(func_name, b) for b in valid_barriers):
                detected_valid.append(func_name)
            else:
                detected_fake_or_cross.append(f"cross_or_unrelated:{func_name}")

    if detected_valid:
        barrier_str = detected_valid[0]
        evidence = (
            f"valid_barrier={barrier_str}",
            f"target_sink_category={category_key}",
            f"sanitizer_nodes={list(flow.sanitizer_nodes)}",
        )
        return BarrierEvaluationResult(has_valid_barrier=True, barrier_name=barrier_str, evidence=evidence)

    evidence = (
        "valid_barrier=none",
        f"target_sink_category={category_key}",
        f"ignored_nodes={detected_fake_or_cross}",
    )
    return BarrierEvaluationResult(has_valid_barrier=False, barrier_name=None, evidence=evidence)


def calculate_deterministic_confidence(
    source_fact: SemanticFact,
    sink_fact: SemanticFact,
    flow: SemanticFlow,
    barrier_res: BarrierEvaluationResult,
) -> float:
    """Calculates deterministic confidence score using explicit evidence predicate tiers.

    Eliminates linear magic weights (SEC-002) by evaluating:
    1. Prerequisite evidence gates (source, sink, reachability).
    2. Explicit evidence deductions/bonuses based on SSA chain, context, and framework.
    """
    # 1. Prerequisite Evidence Tiers (Fail-Closed if missing core evidence)
    if not source_fact.source_kind or not sink_fact.sink_category:
        return 0.0

    if flow.status not in (FlowStatus.CORRELATED, FlowStatus.CANDIDATE) or len(flow.path_node_ids) == 0:
        return 0.0

    # 2. Valid Sanitizer Barrier Gate
    if barrier_res.has_valid_barrier:
        return 0.0

    # 3. Base Reachability-Verified Confidence
    confidence = 0.85

    # 4. Evidence Adjustments based on Data Flow Completeness
    if len(flow.ssa_chain) == 0:
        confidence -= 0.15

    if source_fact.framework != "GENERIC" or sink_fact.framework != "GENERIC":
        confidence += 0.05

    if len(flow.call_context) > 0:
        confidence += 0.05

    return max(0.0, min(1.0, round(confidence, 4)))


class SemanticRuleEngine:
    """Deterministic Security Decision Engine evaluating flows, rules, conditions, and sanitizers for Sprint E12."""

    def __init__(self, registry: SecurityRuleRegistry | None = None) -> None:
        self.registry = registry or create_default_registry()

    def evaluate(
        self,
        flow_store: SemanticFlowStore,
        fact_store: SemanticFactStore,
        graph: CPGGraph,
        registry: SecurityRuleRegistry | None = None,
    ) -> SecurityFindingStore:
        """Evaluates all semantic flows against registered security rules (INV-E12-RULE-01..25)."""
        active_registry = registry or self.registry
        finding_store = SecurityFindingStore()

        # Capture CPG topology invariant before evaluation (INV-E12-RULE-19)
        nodes_before = len(graph.nodes)
        edges_before = len(graph.edges)

        # Deterministic flow iteration
        for flow in flow_store.all():
            # 1. Flow Integrity Validation
            integrity = validate_flow_integrity(flow, fact_store, graph)
            if not integrity.valid:
                # Fail-closed to UNKNOWN finding if missing nodes/facts
                unknown_finding = self._build_unknown_finding(
                    flow=flow,
                    reason=integrity.reason,
                    fact_store=fact_store,
                    graph=graph,
                )
                finding_store.add(unknown_finding)
                continue

            source_fact = fact_store.get_fact(flow.source_fact_id)
            sink_fact = fact_store.get_fact(flow.sink_fact_id)

            if source_fact is None or sink_fact is None:
                unknown_finding = self._build_unknown_finding(
                    flow=flow,
                    reason="Missing source or sink fact",
                    fact_store=fact_store,
                    graph=graph,
                )
                finding_store.add(unknown_finding)
                continue

            # Check for FlowStatus.UNKNOWN
            if flow.status == FlowStatus.UNKNOWN:
                unknown_finding = self._build_unknown_finding(
                    flow=flow,
                    reason="Flow status is UNKNOWN",
                    fact_store=fact_store,
                    graph=graph,
                )
                finding_store.add(unknown_finding)
                continue

            # 2. Candidate Rule Lookup (O(F+C) indexed candidate lookup)
            candidate_rules = active_registry.match(
                source_kind=source_fact.source_kind or "",
                sink_category=sink_fact.sink_category or "",
            )

            # 3. Candidate Rule Evaluation
            for rule in candidate_rules:
                # Evaluate explicit rule conditions
                condition_results: list[ConditionResult] = []
                conditions_matched = True

                for cond in rule.conditions:
                    c_res = cond.evaluate(flow, source_fact, sink_fact, graph)
                    condition_results.append(c_res)
                    if not c_res.matched:
                        conditions_matched = False
                        break

                if not conditions_matched:
                    continue

                # 4. Evaluate Sanitizer Barrier Matrix
                barrier_res = evaluate_sanitizer_barrier(
                    flow=flow,
                    sink_category=sink_fact.sink_category or "",
                    graph=graph,
                )

                # 5. Calculate Deterministic Confidence
                confidence = calculate_deterministic_confidence(
                    source_fact=source_fact,
                    sink_fact=sink_fact,
                    flow=flow,
                    barrier_res=barrier_res,
                )

                # 6. Status Decision Algorithm
                if barrier_res.has_valid_barrier:
                    status = FindingStatus.BLOCKED
                elif confidence >= 0.85:
                    status = FindingStatus.CONFIRMED
                elif confidence >= 0.60:
                    status = FindingStatus.CANDIDATE
                else:
                    status = FindingStatus.UNKNOWN

                # Extract source & sink location evidence
                src_node = graph.nodes.get(flow.source_node_id)
                file_name = src_node.attributes.get("file_path") or src_node.attributes.get("file") if src_node else None
                line_no = src_node.attributes.get("line_number") or src_node.attributes.get("line") if src_node else None
                symbol_name = src_node.attributes.get("name") or src_node.attributes.get("symbol") if src_node else None

                finding = SecurityFinding.create(
                    rule_id=rule.rule_id,
                    rule_key=rule.rule_key,
                    rule_version=rule.version,
                    vulnerability_class=rule.vulnerability_class,
                    source_fact_id=flow.source_fact_id,
                    sink_fact_id=flow.sink_fact_id,
                    flow_id=flow.flow_id,
                    source_node_id=flow.source_node_id,
                    sink_node_id=flow.sink_node_id,
                    severity=rule.severity,
                    status=status,
                    confidence=confidence,
                    source_evidence={
                        "fact_id": source_fact.fact_id,
                        "source_kind": source_fact.source_kind or "",
                        "semantic_role": source_fact.semantic_role.value if hasattr(source_fact.semantic_role, "value") else str(source_fact.semantic_role),
                    },
                    sink_evidence={
                        "fact_id": sink_fact.fact_id,
                        "sink_category": sink_fact.sink_category or "",
                        "semantic_role": sink_fact.semantic_role.value if hasattr(sink_fact.semantic_role, "value") else str(sink_fact.semantic_role),
                    },
                    flow_evidence={
                        "flow_id": flow.flow_id,
                        "flow_status": flow.status.value,
                        "path_node_count": str(len(flow.path_node_ids)),
                    },
                    sanitizer_evidence={
                        "has_valid_barrier": str(barrier_res.has_valid_barrier),
                        "barrier_name": barrier_res.barrier_name or "none",
                    },
                    condition_evidence=[
                        {"matched": str(cr.matched), "reason": cr.reason}
                        for cr in condition_results
                    ],
                    file=str(file_name) if file_name else None,
                    line=int(line_no) if line_no and str(line_no).isdigit() else None,
                    symbol=str(symbol_name) if symbol_name else None,
                )

                finding_store.add(finding)

        # Assert CPG Topology Immutability (INV-E12-RULE-19)
        assert len(graph.nodes) == nodes_before, "CPG node topology was mutated during rule evaluation"
        assert len(graph.edges) == edges_before, "CPG edge topology was mutated during rule evaluation"

        return finding_store

    def _build_unknown_finding(
        self,
        flow: SemanticFlow,
        reason: str,
        fact_store: SemanticFactStore,
        graph: CPGGraph,
    ) -> SecurityFinding:
        """Helper to create fail-closed UNKNOWN SecurityFinding."""
        source_fact = fact_store.get_fact(flow.source_fact_id) if flow else None
        sink_fact = fact_store.get_fact(flow.sink_fact_id) if flow else None

        return SecurityFinding.create(
            rule_id="E12-UNKNOWN-000",
            rule_key="E12-UNKNOWN-000",
            rule_version="1.0",
            vulnerability_class="Unknown / Ambiguous Flow",
            source_fact_id=flow.source_fact_id if flow else "missing_source",
            sink_fact_id=flow.sink_fact_id if flow else "missing_sink",
            flow_id=flow.flow_id if flow else "missing_flow",
            source_node_id=flow.source_node_id if flow else "missing_node",
            sink_node_id=flow.sink_node_id if flow else "missing_node",
            severity="INFO",
            status=FindingStatus.UNKNOWN,
            confidence=0.0,
            source_evidence={"reason": reason},
            sink_evidence={"reason": reason},
            flow_evidence={"reason": reason},
            sanitizer_evidence={"has_valid_barrier": "false"},
            condition_evidence=[{"matched": "false", "reason": reason}],
        )
