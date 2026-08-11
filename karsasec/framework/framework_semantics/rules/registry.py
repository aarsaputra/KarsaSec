"""Rule Registry and O(1) GraphRuleIndex for GraphSecurityRule lookup by SemanticNodeType."""

from __future__ import annotations

import threading
from collections import defaultdict

from karsasec.framework.framework_semantics.rules.schema import GraphSecurityRule
from karsasec.framework.framework_semantics.rules.validator import GraphRuleValidationError
from karsasec.framework.semantic_models import SemanticNodeType


class GraphRuleRegistry:
    """Thread-safe registry managing GraphSecurityRule instances indexed by SemanticNodeType."""

    def __init__(self) -> None:
        self._rules_by_id: dict[str, GraphSecurityRule] = {}
        self._rules_by_node_type: dict[SemanticNodeType, list[GraphSecurityRule]] = defaultdict(list)
        self._lock = threading.Lock()

    def register(self, rule: GraphSecurityRule) -> None:
        """Registers a GraphSecurityRule into the registry.

        Raises:
            GraphRuleValidationError: If duplicate Rule ID is detected.
        """
        with self._lock:
            if rule.id in self._rules_by_id:
                raise GraphRuleValidationError(f"Duplicate Rule ID '{rule.id}' detected in registry.")

            self._rules_by_id[rule.id] = rule
            self._rules_by_node_type[rule.target_node_type].append(rule)

    def get_rule_by_id(self, rule_id: str) -> GraphSecurityRule | None:
        """Retrieves rule by unique ID."""
        with self._lock:
            return self._rules_by_id.get(rule_id)

    def get_rules_for_node_type(self, node_type: SemanticNodeType | str) -> tuple[GraphSecurityRule, ...]:
        """Retrieves candidate rules matching target SemanticNodeType ordered deterministically by rule ID."""
        target_type = SemanticNodeType(node_type) if isinstance(node_type, str) else node_type
        with self._lock:
            rules = self._rules_by_node_type.get(target_type, [])
            return tuple(sorted(rules, key=lambda r: r.id))

    def list_rules(self) -> tuple[GraphSecurityRule, ...]:
        """Returns all registered active rules ordered deterministically by rule ID."""
        with self._lock:
            return tuple(sorted(self._rules_by_id.values(), key=lambda r: r.id))

    def clear(self) -> None:
        """Clears all registered rules."""
        with self._lock:
            self._rules_by_id.clear()
            self._rules_by_node_type.clear()
