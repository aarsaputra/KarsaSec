"""Strict validator for GraphSecurityRule definitions enforcing frozen schema and predicate rules."""

from __future__ import annotations

import re
from typing import Any

from karsasec.framework.framework_semantics.rules.schema import (
    GraphRuleOutput,
    GraphRuleTraversal,
    GraphSecurityRule,
)
from karsasec.framework.semantic_models import SemanticEdgeType, SemanticNodeType
from karsasec.rules.enums import Confidence, Severity

RULE_ID_PATTERN = re.compile(r"^KS-FLASK-[A-Z0-9_-]{2,15}-\d{4}$")

ALLOWED_PREDICATE_KEYS = {
    "node_type_equals",
    "has_attribute",
    "attribute_equals",
    "attribute_contains",
    "incoming_edge",
    "outgoing_edge",
    "edge_count",
    "flow_taint_state_equals",
    "source_kind_equals",
    "sink_kind_equals",
    "is_sink_compatible",
    "is_dangerous_sink",
    "all",
    "any",
    "not",
}

ALLOWED_INCOMING_EDGE_KEYS = {"type", "source_type", "attributes", "source_attributes"}
ALLOWED_OUTGOING_EDGE_KEYS = {"type", "target_type", "attributes", "target_attributes"}
ALLOWED_EDGE_COUNT_KEYS = {"direction", "min_count", "max_count"}


class GraphRuleValidationError(ValueError):
    """Raised when a GraphSecurityRule definition fails schema or predicate validation."""


def _validate_node_type_str(raw_type: str, context: str) -> SemanticNodeType:
    try:
        return SemanticNodeType(raw_type.upper())
    except ValueError:
        valid_types = [t.value for t in SemanticNodeType]
        raise GraphRuleValidationError(
            f"Invalid node_type '{raw_type}' in {context}. Supported node types: {valid_types}"
        )


def _validate_edge_type_str(raw_type: str, context: str) -> SemanticEdgeType:
    try:
        return SemanticEdgeType(raw_type.upper())
    except ValueError:
        valid_types = [t.value for t in SemanticEdgeType]
        raise GraphRuleValidationError(
            f"Invalid edge_type '{raw_type}' in {context}. Supported edge types: {valid_types}"
        )


def _validate_condition_block(cond: Any, context: str) -> None:
    if isinstance(cond, list):
        for idx, sub_cond in enumerate(cond):
            _validate_condition_block(sub_cond, f"{context}[{idx}]")
        return

    if not isinstance(cond, dict):
        raise GraphRuleValidationError(f"Condition block in {context} must be a dictionary.")

    for key, val in cond.items():
        if key not in ALLOWED_PREDICATE_KEYS:
            raise GraphRuleValidationError(
                f"Unknown or unsupported predicate key '{key}' in {context}. "
                f"Allowed predicates: {sorted(ALLOWED_PREDICATE_KEYS)}"
            )

        if key in ("all", "any"):
            if not isinstance(val, list) or len(val) == 0:
                raise GraphRuleValidationError(f"Predicate '{key}' in {context} must be a non-empty list.")
            _validate_condition_block(val, f"{context}.{key}")

        elif key == "not":
            if not isinstance(val, dict):
                raise GraphRuleValidationError(f"Predicate 'not' in {context} must be a dictionary condition block.")
            _validate_condition_block(val, f"{context}.not")

        elif key == "node_type_equals":
            if not isinstance(val, str):
                raise GraphRuleValidationError(f"Predicate 'node_type_equals' in {context} must be a string.")
            _validate_node_type_str(val, f"{context}.node_type_equals")

        elif key == "has_attribute":
            if not isinstance(val, str):
                raise GraphRuleValidationError(f"Predicate 'has_attribute' in {context} must be a string.")

        elif key in ("attribute_equals", "attribute_contains"):
            if not isinstance(val, dict) or "key" not in val or "value" not in val:
                raise GraphRuleValidationError(
                    f"Predicate '{key}' in {context} must be a dict containing 'key' and 'value'."
                )

        elif key == "incoming_edge":
            if not isinstance(val, dict):
                raise GraphRuleValidationError(f"Predicate 'incoming_edge' in {context} must be a dictionary.")
            for k in val:
                if k not in ALLOWED_INCOMING_EDGE_KEYS:
                    raise GraphRuleValidationError(
                        f"Unknown key '{k}' in incoming_edge predicate at {context}. Allowed: {sorted(ALLOWED_INCOMING_EDGE_KEYS)}"
                    )
            if "type" in val:
                _validate_edge_type_str(str(val["type"]), f"{context}.incoming_edge.type")
            if "source_type" in val:
                _validate_node_type_str(str(val["source_type"]), f"{context}.incoming_edge.source_type")

        elif key == "outgoing_edge":
            if not isinstance(val, dict):
                raise GraphRuleValidationError(f"Predicate 'outgoing_edge' in {context} must be a dictionary.")
            for k in val:
                if k not in ALLOWED_OUTGOING_EDGE_KEYS:
                    raise GraphRuleValidationError(
                        f"Unknown key '{k}' in outgoing_edge predicate at {context}. Allowed: {sorted(ALLOWED_OUTGOING_EDGE_KEYS)}"
                    )
            if "type" in val:
                _validate_edge_type_str(str(val["type"]), f"{context}.outgoing_edge.type")
            if "target_type" in val:
                _validate_node_type_str(str(val["target_type"]), f"{context}.outgoing_edge.target_type")

        elif key == "edge_count":
            if not isinstance(val, dict):
                raise GraphRuleValidationError(f"Predicate 'edge_count' in {context} must be a dictionary.")
            for k in val:
                if k not in ALLOWED_EDGE_COUNT_KEYS:
                    raise GraphRuleValidationError(
                        f"Unknown key '{k}' in edge_count predicate at {context}. Allowed: {sorted(ALLOWED_EDGE_COUNT_KEYS)}"
                    )


def validate_graph_rule_dict(raw_data: dict[str, Any]) -> GraphSecurityRule:
    """Validates raw dictionary data against GraphSecurityRule schema and returns immutable GraphSecurityRule.

    Raises:
        GraphRuleValidationError: If any validation rule, bounds check, or schema contract is violated.
    """
    if not isinstance(raw_data, dict):
        raise GraphRuleValidationError("Graph rule data must be a dictionary.")

    rule_sec = raw_data.get("rule")
    if not isinstance(rule_sec, dict):
        raise GraphRuleValidationError("Missing top-level 'rule' dictionary block.")

    rule_id = rule_sec.get("id")
    if not rule_id or not isinstance(rule_id, str):
        raise GraphRuleValidationError("Graph rule must have a string 'id' under 'rule'.")

    if not RULE_ID_PATTERN.match(rule_id):
        raise GraphRuleValidationError(
            f"Invalid Graph Rule ID format '{rule_id}'. Expected pattern like 'KS-FLASK-AUTH-0001'."
        )

    version = str(rule_sec.get("version", "1.0"))
    framework = str(rule_sec.get("framework", "FLASK")).upper()

    metadata = raw_data.get("metadata", {})
    if not isinstance(metadata, dict):
        raise GraphRuleValidationError("Section 'metadata' must be a dictionary.")

    target_sec = raw_data.get("target")
    if not isinstance(target_sec, dict) or "node_type" not in target_sec:
        raise GraphRuleValidationError("Section 'target' must be a dictionary containing 'node_type'.")

    target_node_type = _validate_node_type_str(str(target_sec["node_type"]), "target.node_type")

    cond_sec = raw_data.get("conditions")
    if not isinstance(cond_sec, dict) or len(cond_sec) == 0:
        raise GraphRuleValidationError("Section 'conditions' must be a non-empty dictionary.")

    _validate_condition_block(cond_sec, "conditions")

    traversal_sec = raw_data.get("traversal", {})
    if not isinstance(traversal_sec, dict):
        raise GraphRuleValidationError("Section 'traversal' must be a dictionary.")

    max_depth = int(traversal_sec.get("max_depth", 1))
    if not (1 <= max_depth <= 2):
        raise GraphRuleValidationError(f"Invalid max_depth '{max_depth}'. Must satisfy 1 <= max_depth <= 2.")

    max_nodes_visited = int(traversal_sec.get("max_nodes_visited", 100))
    if not (1 <= max_nodes_visited <= 100):
        raise GraphRuleValidationError(
            f"Invalid max_nodes_visited '{max_nodes_visited}'. Must satisfy 1 <= max_nodes_visited <= 100."
        )

    max_edges_examined = int(traversal_sec.get("max_edges_examined", 200))
    if not (1 <= max_edges_examined <= 200):
        raise GraphRuleValidationError(
            f"Invalid max_edges_examined '{max_edges_examined}'. Must satisfy 1 <= max_edges_examined <= 200."
        )

    traversal_obj = GraphRuleTraversal(
        max_depth=max_depth,
        max_nodes_visited=max_nodes_visited,
        max_edges_examined=max_edges_examined,
    )

    out_sec = raw_data.get("output")
    if not isinstance(out_sec, dict):
        raise GraphRuleValidationError("Section 'output' must be a dictionary.")

    raw_sev = out_sec.get("severity")
    if not raw_sev:
        raise GraphRuleValidationError("Section 'output' must specify 'severity'.")
    try:
        severity = Severity(str(raw_sev).upper())
    except ValueError:
        valid_sevs = [s.value for s in Severity]
        raise GraphRuleValidationError(f"Invalid severity '{raw_sev}'. Supported: {valid_sevs}")

    raw_conf = str(out_sec.get("confidence", "CONFIDENT")).upper()
    conf_map = {
        "HIGH": Confidence.CONFIDENT,
        "MEDIUM": Confidence.LIKELY,
        "LOW": Confidence.POSSIBLE,
        "CONFIDENT": Confidence.CONFIDENT,
        "LIKELY": Confidence.LIKELY,
        "POSSIBLE": Confidence.POSSIBLE,
    }
    if raw_conf not in conf_map:
        raise GraphRuleValidationError(f"Invalid confidence '{raw_conf}'. Supported: {sorted(conf_map.keys())}")
    confidence = conf_map[raw_conf]

    message = str(out_sec.get("message", "Potential security issue detected."))
    remediation = str(out_sec.get("remediation", "Review and sanitize application security configuration."))

    output_obj = GraphRuleOutput(
        severity=severity,
        confidence=confidence,
        message=message,
        remediation=remediation,
    )

    return GraphSecurityRule(
        id=rule_id,
        version=version,
        framework=framework,
        metadata=metadata,
        target_node_type=target_node_type,
        conditions=cond_sec,
        traversal=traversal_obj,
        output=output_obj,
    )
