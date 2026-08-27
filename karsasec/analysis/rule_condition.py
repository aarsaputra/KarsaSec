"""Declarative, AST-less RuleCondition engine and ConditionResult for Sprint E12."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING

from karsasec.analysis.semantic_flow import FlowStatus

if TYPE_CHECKING:
    from karsasec.analysis.semantic_flow import SemanticFlow
    from karsasec.cpg.models import CPGGraph
    from karsasec.framework.semantic_fact import SemanticFact


@dataclass(frozen=True)
class ConditionResult:
    """Immutable result of a RuleCondition evaluation with explainable evidence trace."""

    matched: bool
    reason: str
    evidence: tuple[str, ...] = ()


class RuleCondition(ABC):
    """Abstract base class for declarative rule conditions (INV-E12-RULE-06: No eval/exec/compile)."""

    @abstractmethod
    def evaluate(
        self,
        flow: SemanticFlow,
        source_fact: SemanticFact,
        sink_fact: SemanticFact,
        graph: CPGGraph,
    ) -> ConditionResult:
        """Evaluates condition against semantic context."""
        ...


class SourceKindCondition(RuleCondition):
    """Matches source fact's source_kind."""

    def __init__(self, expected_kinds: tuple[str, ...] | list[str]) -> None:
        self.expected_kinds = tuple(k.lower() for k in expected_kinds)

    def evaluate(
        self,
        flow: SemanticFlow,
        source_fact: SemanticFact,
        sink_fact: SemanticFact,
        graph: CPGGraph,
    ) -> ConditionResult:
        actual = (source_fact.source_kind or "").lower()
        matched = actual in self.expected_kinds or "*" in self.expected_kinds
        reason = (
            f"Source kind '{actual}' matches expected kinds {self.expected_kinds}"
            if matched
            else f"Source kind '{actual}' does not match {self.expected_kinds}"
        )
        evidence = (f"source_kind={actual}", f"source_fact_id={source_fact.fact_id}")
        return ConditionResult(matched=matched, reason=reason, evidence=evidence)


class SinkCategoryCondition(RuleCondition):
    """Matches sink fact's sink_category."""

    def __init__(self, expected_categories: tuple[str, ...] | list[str]) -> None:
        self.expected_categories = tuple(c.lower() for c in expected_categories)

    def evaluate(
        self,
        flow: SemanticFlow,
        source_fact: SemanticFact,
        sink_fact: SemanticFact,
        graph: CPGGraph,
    ) -> ConditionResult:
        actual = (sink_fact.sink_category or "").lower()
        matched = actual in self.expected_categories or "*" in self.expected_categories
        reason = (
            f"Sink category '{actual}' matches expected categories {self.expected_categories}"
            if matched
            else f"Sink category '{actual}' does not match {self.expected_categories}"
        )
        evidence = (f"sink_category={actual}", f"sink_fact_id={sink_fact.fact_id}")
        return ConditionResult(matched=matched, reason=reason, evidence=evidence)


class SemanticRoleCondition(RuleCondition):
    """Validates source and sink semantic roles."""

    def __init__(self, required_source_role: str = "http_input", required_sink_role: str = "security_sink") -> None:
        self.required_source_role = required_source_role.lower()
        self.required_sink_role = required_sink_role.lower()

    def evaluate(
        self,
        flow: SemanticFlow,
        source_fact: SemanticFact,
        sink_fact: SemanticFact,
        graph: CPGGraph,
    ) -> ConditionResult:
        src_role = (source_fact.semantic_role.value if hasattr(source_fact.semantic_role, "value") else str(source_fact.semantic_role)).lower()
        snk_role = (sink_fact.semantic_role.value if hasattr(sink_fact.semantic_role, "value") else str(sink_fact.semantic_role)).lower()

        matched = (src_role == self.required_source_role) and (snk_role == self.required_sink_role)
        reason = (
            f"Semantic roles ({src_role}, {snk_role}) match required ({self.required_source_role}, {self.required_sink_role})"
            if matched
            else f"Semantic roles ({src_role}, {snk_role}) do not match ({self.required_source_role}, {self.required_sink_role})"
        )
        evidence = (f"source_role={src_role}", f"sink_role={snk_role}")
        return ConditionResult(matched=matched, reason=reason, evidence=evidence)


class FlowStatusCondition(RuleCondition):
    """Validates that flow status is within allowed statuses."""

    def __init__(self, allowed_statuses: tuple[FlowStatus | str, ...] | list[FlowStatus | str]) -> None:
        self.allowed_statuses = tuple(
            s if isinstance(s, FlowStatus) else FlowStatus(s) for s in allowed_statuses
        )

    def evaluate(
        self,
        flow: SemanticFlow,
        source_fact: SemanticFact,
        sink_fact: SemanticFact,
        graph: CPGGraph,
    ) -> ConditionResult:
        matched = flow.status in self.allowed_statuses
        reason = (
            f"Flow status '{flow.status.value}' is in allowed statuses {[s.value for s in self.allowed_statuses]}"
            if matched
            else f"Flow status '{flow.status.value}' is not in {[s.value for s in self.allowed_statuses]}"
        )
        evidence = (f"flow_status={flow.status.value}", f"flow_id={flow.flow_id}")
        return ConditionResult(matched=matched, reason=reason, evidence=evidence)


class MinimumConfidenceCondition(RuleCondition):
    """Validates that flow confidence meets minimum threshold."""

    def __init__(self, threshold: float = 0.60) -> None:
        self.threshold = round(threshold, 4)

    def evaluate(
        self,
        flow: SemanticFlow,
        source_fact: SemanticFact,
        sink_fact: SemanticFact,
        graph: CPGGraph,
    ) -> ConditionResult:
        matched = flow.confidence >= self.threshold
        reason = (
            f"Flow confidence {flow.confidence:.4f} meets threshold {self.threshold:.4f}"
            if matched
            else f"Flow confidence {flow.confidence:.4f} below threshold {self.threshold:.4f}"
        )
        evidence = (f"confidence={flow.confidence:.4f}", f"threshold={self.threshold:.4f}")
        return ConditionResult(matched=matched, reason=reason, evidence=evidence)


class SanitizerAbsentCondition(RuleCondition):
    """Validates that no blocked sanitizers are present in flow.sanitizer_nodes."""

    def __init__(self, blocked_sanitizers: tuple[str, ...] | list[str]) -> None:
        self.blocked_sanitizers = tuple(s.lower() for s in blocked_sanitizers)

    def evaluate(
        self,
        flow: SemanticFlow,
        source_fact: SemanticFact,
        sink_fact: SemanticFact,
        graph: CPGGraph,
    ) -> ConditionResult:
        # Check node names/attributes for blocked sanitizers
        detected: list[str] = []
        for nid in flow.sanitizer_nodes:
            if nid in graph.nodes:
                node = graph.nodes[nid]
                name = (node.attributes.get("name") or node.attributes.get("function_name") or node.label).lower()
                if any(b in name for b in self.blocked_sanitizers):
                    detected.append(name)

        matched = len(detected) == 0
        reason = (
            "No blocked sanitizers detected in flow path"
            if matched
            else f"Blocked sanitizers detected: {detected}"
        )
        evidence = (f"sanitizer_nodes={list(flow.sanitizer_nodes)}", f"detected_sanitizers={detected}")
        return ConditionResult(matched=matched, reason=reason, evidence=evidence)


class SanitizerPresentCondition(RuleCondition):
    """Validates that a specific valid sanitizer is present in flow."""

    def __init__(self, required_sanitizer: str) -> None:
        self.required_sanitizer = required_sanitizer.lower()

    def evaluate(
        self,
        flow: SemanticFlow,
        source_fact: SemanticFact,
        sink_fact: SemanticFact,
        graph: CPGGraph,
    ) -> ConditionResult:
        detected = False
        for nid in flow.sanitizer_nodes:
            if nid in graph.nodes:
                node = graph.nodes[nid]
                name = (node.attributes.get("name") or node.attributes.get("function_name") or node.label).lower()
                if self.required_sanitizer in name:
                    detected = True
                    break

        reason = (
            f"Required sanitizer '{self.required_sanitizer}' detected"
            if detected
            else f"Required sanitizer '{self.required_sanitizer}' not found"
        )
        evidence = (f"required_sanitizer={self.required_sanitizer}", f"present={detected}")
        return ConditionResult(matched=detected, reason=reason, evidence=evidence)


class PathContainsNodeCondition(RuleCondition):
    """Validates that path includes specific node ID."""

    def __init__(self, target_node_id: str) -> None:
        self.target_node_id = target_node_id

    def evaluate(
        self,
        flow: SemanticFlow,
        source_fact: SemanticFact,
        sink_fact: SemanticFact,
        graph: CPGGraph,
    ) -> ConditionResult:
        matched = self.target_node_id in flow.path_node_ids
        reason = (
            f"Target node '{self.target_node_id}' present in path"
            if matched
            else f"Target node '{self.target_node_id}' absent from path"
        )
        evidence = (f"target_node_id={self.target_node_id}", f"path_length={len(flow.path_node_ids)}")
        return ConditionResult(matched=matched, reason=reason, evidence=evidence)


class FrameworkCondition(RuleCondition):
    """Validates framework context against allowed framework list."""

    def __init__(self, allowed_frameworks: tuple[str, ...] | list[str]) -> None:
        self.allowed_frameworks = tuple(f.upper() for f in allowed_frameworks)

    def evaluate(
        self,
        flow: SemanticFlow,
        source_fact: SemanticFact,
        sink_fact: SemanticFact,
        graph: CPGGraph,
    ) -> ConditionResult:
        fw_src = (source_fact.framework or "GENERIC").upper()
        fw_snk = (sink_fact.framework or "GENERIC").upper()

        matched = "GENERIC" in self.allowed_frameworks or fw_src in self.allowed_frameworks or fw_snk in self.allowed_frameworks
        reason = (
            f"Frameworks ({fw_src}, {fw_snk}) match allowed {self.allowed_frameworks}"
            if matched
            else f"Frameworks ({fw_src}, {fw_snk}) do not match allowed {self.allowed_frameworks}"
        )
        evidence = (f"source_framework={fw_src}", f"sink_framework={fw_snk}")
        return ConditionResult(matched=matched, reason=reason, evidence=evidence)
