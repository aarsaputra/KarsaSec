"""YAML Rule Loader and thread-safe Rule Memory Cache module."""

import threading
from pathlib import Path
from typing import Dict, List, Optional
import yaml

from karsasec.rules.schema import Rule, validate_rule_dict

class RuleCache:
    """Thread-safe in-memory cache for parsed and validated Rule objects."""

    def __init__(self) -> None:
        self._cache: Dict[str, Rule] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Rule]:
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
    """Parses and validates security rules defined in YAML files."""

    def __init__(self, cache: Optional[RuleCache] = None) -> None:
        self.cache = cache or RuleCache()

    def load_file(self, file_path: Path) -> Rule:
        """Loads and validates a single YAML rule file."""
        resolved_path = file_path.resolve()
        cache_key = str(resolved_path)

        cached_rule = self.cache.get(cache_key)
        if cached_rule:
            return cached_rule

        if not resolved_path.exists():
            raise ValueError(f"Rule file not found: {resolved_path}")

        try:
            content = resolved_path.read_text(encoding="utf-8")
        except Exception as ex:
            raise ValueError(f"Failed reading rule file '{resolved_path}': {str(ex)}")

        rule = self.load_string(content, cache_key=cache_key)
        return rule

    def load_string(self, yaml_content: str, cache_key: Optional[str] = None) -> Rule:
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

    def load_directory(self, dir_path: Path) -> List[Rule]:
        """Recursively scans directory for .yaml/.yml rule files and returns loaded rules."""
        resolved_dir = dir_path.resolve()
        rules: List[Rule] = []

        if not resolved_dir.exists() or not resolved_dir.is_dir():
            return rules

        for path in sorted(resolved_dir.rglob("*")):
            if path.is_file() and path.suffix.lower() in (".yaml", ".yml"):
                try:
                    rule = self.load_file(path)
                    rules.append(rule)
                except Exception:
                    # Skip or propagate depending on configuration
                    pass

        return rules
