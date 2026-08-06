"""YAML Rule Loader and thread-safe Rule Memory Cache module."""

import threading
from pathlib import Path

import yaml

from karsasec.rules.predicate_resolver import PredicateResolver
from karsasec.rules.schema import Rule, validate_rule_dict


class RuleCache:
    """Thread-safe in-memory cache for parsed and validated Rule objects."""

    def __init__(self) -> None:
        self._cache: dict[str, Rule] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Rule | None:
        """Retrieves a cached Rule by key."""
        with self._lock:
            return self._cache.get(key)

    def put(self, key: str, rule: Rule) -> None:
        """Stores a Rule in memory cache."""
        with self._lock:
            self._cache[key] = rule

    def clear(self) -> None:
        """Clears memory cache."""
        with self._lock:
            self._cache.clear()


class YAMLRuleLoader:
    """Parses and validates security rules defined in single or multi-rule YAML files."""

    def __init__(self, cache: RuleCache | None = None, predicate_resolver: PredicateResolver | None = None) -> None:
        self.cache = cache or RuleCache()
        self.resolver = predicate_resolver or PredicateResolver()

    def load_file(self, file_path: Path) -> Rule:
        """Loads and validates a single YAML rule file."""
        rules = self.load_file_multi(file_path)
        if not rules:
            raise ValueError(f"No valid rule found in {file_path}")
        return rules[0]

    def load_file_multi(self, file_path: Path) -> list[Rule]:
        """Loads and validates one or multiple YAML rules from a file."""
        resolved_path = file_path.resolve()
        cache_key = str(resolved_path)

        if not resolved_path.exists():
            raise ValueError(f"Rule file not found: {resolved_path}")

        try:
            content = resolved_path.read_text(encoding="utf-8")
        except Exception as ex:
            raise ValueError(f"Failed reading rule file '{resolved_path}': {str(ex)}")

        try:
            raw_data = yaml.safe_load(content)
        except yaml.YAMLError as ye:
            raise ValueError(f"Invalid YAML syntax: {str(ye)}")

        if not raw_data or not isinstance(raw_data, dict):
            raise ValueError("YAML content must evaluate to a dictionary.")

        rules: list[Rule] = []
        if "rules" in raw_data and isinstance(raw_data["rules"], list):
            for idx, item in enumerate(raw_data["rules"]):
                if isinstance(item, dict):
                    item_key = f"{cache_key}#{idx}"
                    cached = self.cache.get(item_key)
                    if cached:
                        rules.append(cached)
                    else:
                        resolved_item = self.resolver.resolve_rule_dict(item)
                        r = validate_rule_dict(resolved_item)
                        self.cache.put(item_key, r)
                        rules.append(r)
        elif "rule" in raw_data:
            cached = self.cache.get(cache_key)
            if cached:
                rules.append(cached)
            else:
                resolved_item = self.resolver.resolve_rule_dict(raw_data)
                r = validate_rule_dict(resolved_item)
                self.cache.put(cache_key, r)
                rules.append(r)

        return rules

    def load_string(self, yaml_content: str, cache_key: str | None = None) -> Rule:
        """Parses and validates a YAML rule from a string."""
        if cache_key:
            cached_rule = self.cache.get(cache_key)
            if cached_rule:
                return cached_rule

        try:
            raw_data = yaml.safe_load(yaml_content)
        except yaml.YAMLError as ye:
            raise ValueError(f"Invalid YAML syntax: {str(ye)}")

        if not raw_data or not isinstance(raw_data, dict):
            raise ValueError("YAML content must evaluate to a dictionary.")

        rule = validate_rule_dict(raw_data)

        if cache_key:
            self.cache.put(cache_key, rule)

        return rule

    def load_directory(self, dir_path: Path) -> list[Rule]:
        """Recursively scans directory for .yaml/.yml rule files and returns loaded rules."""
        resolved_dir = dir_path.resolve()
        rules: list[Rule] = []

        if not resolved_dir.exists() or not resolved_dir.is_dir():
            return rules

        for path in sorted(resolved_dir.rglob("*")):
            if path.is_file() and path.suffix.lower() in (".yaml", ".yml"):
                try:
                    loaded = self.load_file_multi(path)
                    rules.extend(loaded)
                except Exception:
                    pass

        return rules
