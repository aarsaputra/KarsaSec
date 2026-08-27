"""SecurityRuleRegistry with indexed candidate matching (O(F+C)) and built-in rules for Sprint E12."""

from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING

from karsasec.analysis.security_rule import SecurityRule

if TYPE_CHECKING:
    pass

logger = logging.getLogger("karsasec.analysis.rule_registry")


class SecurityRuleRegistry:
    """Thread-safe registry for SecurityRules featuring indexed candidate matching by (source_kind, sink_category)."""

    def __init__(self) -> None:
        self._rules: dict[str, SecurityRule] = {}
        # Index: source_kind -> sink_category -> list[SecurityRule]
        self._index: dict[str, dict[str, list[SecurityRule]]] = {}
        self._lock = threading.RLock()

    def register(self, rule: SecurityRule) -> None:
        """Registers a SecurityRule and updates source_kind/sink_category indices deterministically (INV-E12-RULE-04,05)."""
        with self._lock:
            if rule.rule_id in self._rules or rule.rule_key in self._rules:
                logger.warning("Overwriting registered rule: %s (%s)", rule.rule_key, rule.rule_id)

            self._rules[rule.rule_id] = rule
            self._rules[rule.rule_key] = rule

            for src_kind in rule.source_kinds:
                src_key = src_kind.lower()
                if src_key not in self._index:
                    self._index[src_key] = {}

                for snk_cat in rule.sink_categories:
                    snk_key = snk_cat.lower()
                    if snk_key not in self._index[src_key]:
                        self._index[src_key][snk_key] = []

                    if rule not in self._index[src_key][snk_key]:
                        self._index[src_key][snk_key].append(rule)

    def unregister(self, rule_key_or_id: str) -> bool:
        """Unregisters a rule by key or ID."""
        with self._lock:
            rule = self._rules.get(rule_key_or_id)
            if not rule:
                return False

            self._rules.pop(rule.rule_id, None)
            self._rules.pop(rule.rule_key, None)

            # Rebuild index
            self._rebuild_index()
            return True

    def get(self, rule_key_or_id: str) -> SecurityRule | None:
        """Retrieves a rule by key or ID."""
        with self._lock:
            return self._rules.get(rule_key_or_id)

    def match(self, source_kind: str, sink_category: str) -> tuple[SecurityRule, ...]:
        """Performs indexed O(1) candidate lookup for (source_kind, sink_category) sorted deterministically (INV-E12-RULE-04,05)."""
        src_key = (source_kind or "").lower()
        snk_key = (sink_category or "").lower()

        with self._lock:
            # Check specific match as well as wildcard '*'
            candidates: set[SecurityRule] = set()

            for s_k in (src_key, "*"):
                if s_k in self._index:
                    for k_cat in (snk_key, "*"):
                        if k_cat in self._index[s_k]:
                            candidates.update(self._index[s_k][k_cat])

            # Deterministic sorting by (severity_rank, rule_key, version)
            sorted_candidates = sorted(
                candidates,
                key=lambda r: (r.rule_key, r.version, r.rule_id),
            )
            return tuple(sorted_candidates)

    def all(self) -> tuple[SecurityRule, ...]:
        """Returns all unique registered rules sorted deterministically."""
        with self._lock:
            unique_rules = set(self._rules.values())
            return tuple(sorted(unique_rules, key=lambda r: (r.rule_key, r.version, r.rule_id)))

    def count(self) -> int:
        """Returns count of unique registered rules."""
        with self._lock:
            return len(set(self._rules.values()))

    def clear(self) -> None:
        """Clears all rules and indices."""
        with self._lock:
            self._rules.clear()
            self._index.clear()

    def _rebuild_index(self) -> None:
        """Rebuilds internal indices atomically after unregistration (VULN-002 fix)."""
        new_index: dict[str, dict[str, list[SecurityRule]]] = {}
        with self._lock:
            unique_rules = list(set(self._rules.values()))

        for rule in unique_rules:
            for src_kind in rule.source_kinds:
                src_key = src_kind.lower()
                if src_key not in new_index:
                    new_index[src_key] = {}

                for snk_cat in rule.sink_categories:
                    snk_key = snk_cat.lower()
                    if snk_key not in new_index[src_key]:
                        new_index[src_key][snk_key] = []

                    if rule not in new_index[src_key][snk_key]:
                        new_index[src_key][snk_key].append(rule)

        with self._lock:
            self._index = new_index


def create_builtin_rules() -> tuple[SecurityRule, ...]:
    """Factory creating official Sprint E12 built-in security rules."""
    sql_rule = SecurityRule.create(
        rule_key="E12-SQL-001",
        name="Unsanitized HTTP Input to SQL Sink",
        version="1.0",
        vulnerability_class="SQL Injection",
        source_kinds=["http_user_input", "user_input", "http_input"],
        sink_categories=["sql"],
        blocked_by_sanitizers=["int", "sanitize_sql", "parameterized_query", "prepared_statement"],
        minimum_confidence=0.60,
        severity="HIGH",
    )

    cmd_rule = SecurityRule.create(
        rule_key="E12-CMD-001",
        name="Unsanitized HTTP Input to Command Execution",
        version="1.0",
        vulnerability_class="Command Injection",
        source_kinds=["http_user_input", "user_input", "http_input"],
        sink_categories=["command_execution"],
        blocked_by_sanitizers=["shlex.quote", "command_allowlist", "safe_exec"],
        minimum_confidence=0.60,
        severity="CRITICAL",
    )

    xss_rule = SecurityRule.create(
        rule_key="E12-XSS-001",
        name="Unescaped HTTP Input to HTML Render",
        version="1.0",
        vulnerability_class="Cross-Site Scripting (XSS)",
        source_kinds=["http_user_input", "user_input", "http_input"],
        sink_categories=["html_render"],
        blocked_by_sanitizers=["escape_html", "html_escape", "framework_auto_escape"],
        minimum_confidence=0.60,
        severity="HIGH",
    )

    path_rule = SecurityRule.create(
        rule_key="E12-PATH-001",
        name="HTTP Input to File Path Sink",
        version="1.0",
        vulnerability_class="Path Traversal",
        source_kinds=["http_user_input", "user_input", "http_input"],
        sink_categories=["file_path"],
        blocked_by_sanitizers=["path_allowlist", "realpath_boundary_check", "safe_join", "basename"],
        minimum_confidence=0.60,
        severity="HIGH",
    )

    code_rule = SecurityRule.create(
        rule_key="E12-CODE-001",
        name="HTTP Input to Code Evaluation",
        version="1.0",
        vulnerability_class="Code Injection",
        source_kinds=["http_user_input", "user_input", "http_input"],
        sink_categories=["code_execution"],
        blocked_by_sanitizers=["strict_allowlist", "static_dispatch", "ast.literal_eval"],
        minimum_confidence=0.60,
        severity="CRITICAL",
    )

    return (sql_rule, cmd_rule, xss_rule, path_rule, code_rule)


def create_default_registry() -> SecurityRuleRegistry:
    """Creates a SecurityRuleRegistry pre-populated with built-in rules."""
    registry = SecurityRuleRegistry()
    for rule in create_builtin_rules():
        registry.register(rule)
    return registry
