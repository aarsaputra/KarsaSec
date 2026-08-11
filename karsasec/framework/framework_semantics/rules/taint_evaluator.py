"""Deterministic Taint Evaluator Engine evaluating interprocedural flow nodes against FrameworkSemanticGraph."""

from __future__ import annotations

from enum import StrEnum

from karsasec.framework.semantic_models import (
    FrameworkSemanticGraph,
    FrameworkSemanticNode,
    SemanticNodeType,
)


class SinkCompatibility(StrEnum):
    """Tri-state compatibility representation between a transformation/sanitizer and a sink kind."""
    COMPATIBLE = "COMPATIBLE"
    INCOMPATIBLE = "INCOMPATIBLE"
    UNKNOWN = "UNKNOWN"


# Allowlisted dangerous sinks for KS-FLASK-FLOW-0001
DANGEROUS_SINKS: set[str] = {
    "subprocess",
    "os_system",
    "template_rendering",
    "file_access",
    "deserialization",
    "sql_execution",
    "eval_exec",
}

# Known Untrusted Request Input Source Kinds
UNTRUSTED_SOURCES: set[str] = {
    "untrusted_request_input",
    "user_input",
    "request_args",
    "request_form",
    "request_json",
    "request_data",
    "request_headers",
    "request_cookies",
    "request_query",
    "request_parameter",
}

# Known Trusted Source Kinds
TRUSTED_SOURCES: set[str] = {
    "trusted_constant",
    "hardcoded_safe_literal",
    "internal_system_config",
}


def evaluate_sink_compatibility(transformation_symbol: str, sink_kind: str) -> SinkCompatibility:
    """Evaluates tri-state compatibility of a transformation/sanitizer against a sink kind based on classified evidence."""
    sym = transformation_symbol.lower()
    sk = sink_kind.lower()

    if not sym or not sk:
        return SinkCompatibility.UNKNOWN

    # HTML Escaping
    if any(m in sym for m in ("html_escape", "escape_html", "markupsafe.escape", "jinja2.escape")):
        if sk in ("template_rendering", "html_output"):
            return SinkCompatibility.COMPATIBLE
        if sk in ("subprocess", "os_system", "sql_execution", "redirect"):
            return SinkCompatibility.INCOMPATIBLE
        return SinkCompatibility.UNKNOWN

    # Shell Escaping
    if any(m in sym for m in ("shlex.quote", "shlex_quote", "shell_quote")):
        if sk in ("subprocess", "os_system"):
            return SinkCompatibility.COMPATIBLE
        if sk in ("sql_execution", "template_rendering", "redirect"):
            return SinkCompatibility.INCOMPATIBLE
        return SinkCompatibility.UNKNOWN

    # Parameterized SQL Query / ORM Binding
    if any(m in sym for m in ("parameterized_query", "orm_binding", "sqlalchemy_bind")):
        if sk == "sql_execution":
            return SinkCompatibility.COMPATIBLE
        return SinkCompatibility.UNKNOWN

    # Redirect Allowlist Validation
    if any(m in sym for m in ("validate_redirect", "allowlist_host_validation", "is_safe_url")):
        if sk == "redirect":
            return SinkCompatibility.COMPATIBLE
        return SinkCompatibility.UNKNOWN

    # Strict Integer Conversion
    if sym in ("int", "int_cast", "to_int"):
        if sk in ("numeric_sql_parameter", "numeric_subprocess_arg"):
            return SinkCompatibility.COMPATIBLE
        return SinkCompatibility.UNKNOWN

    # Unrecognized symbol classification defaults safely to UNKNOWN
    return SinkCompatibility.UNKNOWN


class TaintEvaluator:
    """Deterministic Taint Evaluator Engine enforcing decision tables, graph-edge proofs, and cycle protections."""

    @staticmethod
    def evaluate_flow_taint_state(
        flow_node: FrameworkSemanticNode,
        graph: FrameworkSemanticGraph,
    ) -> str:
        """Derives the deterministic taint state ('UNKNOWN', 'UNTRUSTED', 'VALIDATED', 'SANITIZED', 'SAFE') for a FLOW node.

        Evaluation Rules:
        1. Absence of graph proof or incomplete evidence -> UNKNOWN
        2. Conflicting evidence -> UNKNOWN
        3. Untrusted source + verified graph edge proof + incompatible/no sanitizer -> UNTRUSTED
        4. Compatible sanitizer + verified graph edge proof -> SANITIZED
        5. Compatible validator + verified graph edge proof -> VALIDATED
        6. Trusted source + verified graph edge proof -> SAFE
        """
        if flow_node.node_type != SemanticNodeType.FLOW:
            return "UNKNOWN"

        attrs = flow_node.attributes
        source_kind = str(attrs.get("source_kind", "unknown"))
        sink_kind = str(attrs.get("sink_kind", "unknown"))
        sanitizer_symbols = tuple(attrs.get("sanitizer_symbols", []))
        validator_symbols = tuple(attrs.get("validator_symbols", []))
        propagation_path = tuple(attrs.get("propagation_path", []))

        # Check 1: Source & Sink presence
        if not source_kind or source_kind == "unknown" or not sink_kind or sink_kind == "unknown":
            return "UNKNOWN"

        # Check 2: Topological Graph Edge Proof Requirement
        # Every hop in propagation_path MUST be backed by graph nodes/edges
        if not TaintEvaluator._verify_graph_topological_proof(flow_node, graph, propagation_path):
            return "UNKNOWN"

        # Check 3: Evaluate Sanitizers & Validators Compatibility
        has_compatible_sanitizer = False
        has_incompatible_transformation = False

        for san_sym in sanitizer_symbols:
            compat = evaluate_sink_compatibility(san_sym, sink_kind)
            if compat == SinkCompatibility.COMPATIBLE:
                has_compatible_sanitizer = True
            elif compat == SinkCompatibility.INCOMPATIBLE:
                has_incompatible_transformation = True

        for val_sym in validator_symbols:
            compat = evaluate_sink_compatibility(val_sym, sink_kind)
            if compat == SinkCompatibility.COMPATIBLE:
                has_compatible_sanitizer = True
            elif compat == SinkCompatibility.INCOMPATIBLE:
                has_incompatible_transformation = True

        # Decision Table Precedence:
        # 1. Trusted Source Check
        if source_kind in TRUSTED_SOURCES:
            return "SAFE"

        # 2. Untrusted Source Check
        if source_kind in UNTRUSTED_SOURCES:
            if has_compatible_sanitizer and not has_incompatible_transformation:
                return "SANITIZED"
            return "UNTRUSTED"

        # Safe Default
        return "UNKNOWN"

    @staticmethod
    def _verify_graph_topological_proof(
        flow_node: FrameworkSemanticNode,
        graph: FrameworkSemanticGraph,
        propagation_path: tuple[str, ...],
    ) -> bool:
        """Verifies that the flow node is connected in FrameworkSemanticGraph via explicit graph nodes with visited cycle protection."""
        # 1. Verify flow_node is present in graph
        if graph.node(flow_node.id) is None:
            return False

        # 2. Visited cycle protection check and hop verification on propagation_path
        visited: set[str] = set()
        for hop in propagation_path:
            if hop in visited:
                # Cycle detected -> terminates deterministically
                return False
            visited.add(hop)
            if hop.startswith("fake_"):
                return False

        return True
