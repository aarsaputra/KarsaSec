"""Declarative YAML Rule Loader and Cache for GraphSecurityRule definitions."""

from __future__ import annotations

import threading
from pathlib import Path

import yaml

from karsasec.framework.framework_semantics.rules.schema import GraphSecurityRule
from karsasec.framework.framework_semantics.rules.validator import (
    GraphRuleValidationError,
    validate_graph_rule_dict,
)


class GraphRuleCache:
    """Thread-safe in-memory cache for parsed GraphSecurityRule objects."""

    def __init__(self) -> None:
        self._cache: dict[str, GraphSecurityRule] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> GraphSecurityRule | None:
        with self._lock:
            return self._cache.get(key)

    def put(self, key: str, rule: GraphSecurityRule) -> None:
        with self._lock:
            self._cache[key] = rule

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()


class GraphRuleLoader:
    """Parses, validates, and loads declarative GraphSecurityRule definitions from YAML."""

    def __init__(self, cache: GraphRuleCache | None = None) -> None:
        self.cache = cache or GraphRuleCache()

    def load_string(self, yaml_content: str, cache_key: str | None = None) -> GraphSecurityRule:
        """Parses and validates a single GraphSecurityRule from YAML string."""
        if cache_key:
            cached = self.cache.get(cache_key)
            if cached:
                return cached

        try:
            raw_data = yaml.safe_load(yaml_content)
        except yaml.YAMLError as ye:
            raise GraphRuleValidationError(f"Invalid YAML syntax: {str(ye)}")

        if not raw_data or not isinstance(raw_data, dict):
            raise GraphRuleValidationError("YAML content must evaluate to a dictionary.")

        rule = validate_graph_rule_dict(raw_data)

        if cache_key:
            self.cache.put(cache_key, rule)

        return rule

    def load_file(self, file_path: Path) -> GraphSecurityRule:
        """Loads and validates a single GraphSecurityRule from file."""
        resolved_path = file_path.resolve()
        cache_key = str(resolved_path)

        cached = self.cache.get(cache_key)
        if cached:
            return cached

        if not resolved_path.exists():
            raise GraphRuleValidationError(f"Rule file not found: {resolved_path}")

        try:
            content = resolved_path.read_text(encoding="utf-8")
        except Exception as ex:
            raise GraphRuleValidationError(f"Failed reading rule file '{resolved_path}': {str(ex)}")

        rule = self.load_string(content, cache_key=cache_key)
        return rule

    def load_directory(self, dir_path: Path) -> list[GraphSecurityRule]:
        """Recursively loads all YAML rules from directory in deterministic sorted path order."""
        resolved_dir = dir_path.resolve()
        rules: list[GraphSecurityRule] = []
        seen_ids: set[str] = set()

        if not resolved_dir.exists() or not resolved_dir.is_dir():
            return rules

        for path in sorted(resolved_dir.rglob("*")):
            if path.is_file() and path.suffix.lower() in (".yaml", ".yml"):
                rule = self.load_file(path)
                if rule.id in seen_ids:
                    raise GraphRuleValidationError(f"Duplicate Rule ID '{rule.id}' detected in directory scan.")
                seen_ids.add(rule.id)
                rules.append(rule)

        return rules
