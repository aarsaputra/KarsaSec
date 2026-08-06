"""Compile-Time Predicate Resolver and Inheritance Engine for KarsaSec Security Rules."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class PredicateDefinition:
    """Represents a reusable shared predicate definition loaded at compile time."""

    name: str
    version: str
    description: str
    metadata: dict[str, Any]
    sources: list[str] = field(default_factory=list)
    sinks: list[str] = field(default_factory=list)
    sanitizers: list[str] = field(default_factory=list)
    condition: dict[str, Any] = field(default_factory=dict)
    dependencies: list[str] = field(default_factory=list)


class PredicateCycleError(Exception):
    """Raised when a circular reference loop is detected in predicate inheritance."""

    pass


class PredicateNotFoundError(Exception):
    """Raised when a referenced predicate cannot be found in the registry."""

    pass


class PredicateResolver:
    """Loads, validates, and resolves compile-time shared predicates for rule parsing."""

    def __init__(self, predicates_dir: Path | None = None) -> None:
        if predicates_dir is None:
            predicates_dir = Path(__file__).parent / "predicates"
        self.predicates_dir = predicates_dir
        self._predicates: dict[str, PredicateDefinition] = {}
        self._loaded = False

    def load_all_predicates(self) -> None:
        """Discovers and parses all YAML predicate definitions from the predicates directory."""
        if not self.predicates_dir.exists():
            self._loaded = True
            return

        for p_file in self.predicates_dir.glob("*.yaml"):
            try:
                raw_text = p_file.read_text(encoding="utf-8")
                data = yaml.safe_load(raw_text)
                if not data or "predicate" not in data:
                    continue

                p_dict = data["predicate"]
                name = p_dict.get("name")
                if not name:
                    continue

                pred = PredicateDefinition(
                    name=name,
                    version=p_dict.get("version", "1.0.0"),
                    description=p_dict.get("description", ""),
                    metadata=p_dict.get("metadata", {}),
                    sources=p_dict.get("sources", []),
                    sinks=p_dict.get("sinks", []),
                    sanitizers=p_dict.get("sanitizers", []),
                    condition=p_dict.get("condition", {}),
                    dependencies=p_dict.get("dependencies", []),
                )
                self._predicates[name] = pred
            except Exception:
                pass

        self._validate_dependencies_and_cycles()
        self._loaded = True

    def _validate_dependencies_and_cycles(self) -> None:
        """Validates that all predicate dependencies exist and detects cycle loops."""
        for p_name, pred in self._predicates.items():
            visited: set[str] = set()

            def dfs(current: str) -> None:
                if current in visited:
                    raise PredicateCycleError(f"Circular predicate dependency detected involving '{current}'")
                visited.add(current)

                curr_pred = self._predicates.get(current)
                if not curr_pred:
                    raise PredicateNotFoundError(f"Referenced predicate dependency '{current}' not found")

                for dep in curr_pred.dependencies:
                    dfs(dep)

                visited.remove(current)

            dfs(p_name)

    def get_predicate(self, name: str) -> PredicateDefinition:
        """Retrieves a loaded predicate definition by name."""
        if not self._loaded:
            self.load_all_predicates()

        if name not in self._predicates:
            raise PredicateNotFoundError(f"Predicate '{name}' is not registered.")
        return self._predicates[name]

    def resolve_rule_dict(self, rule_dict: dict[str, Any]) -> dict[str, Any]:
        """Resolves `uses: predicate: <name>` inheritance into the rule dictionary at compile time."""
        if not self._loaded:
            self.load_all_predicates()

        uses_block = rule_dict.get("uses")
        if not uses_block or not isinstance(uses_block, dict):
            return rule_dict

        p_name = uses_block.get("predicate")
        if not p_name or not isinstance(p_name, str):
            return rule_dict

        pred = self.get_predicate(p_name)

        # Merge Metadata if absent in rule
        if "metadata" not in rule_dict or not isinstance(rule_dict["metadata"], dict):
            rule_dict["metadata"] = {}

        rule_meta = rule_dict["metadata"]
        for k, v in pred.metadata.items():
            if k not in rule_meta or not rule_meta[k]:
                rule_meta[k] = v

        # Merge Condition
        if "condition" not in rule_dict or not isinstance(rule_dict["condition"], dict):
            rule_dict["condition"] = {}

        rule_cond = rule_dict["condition"]
        pred_cond = pred.condition

        # Merge symbol_triggers
        if "symbol_triggers" not in rule_cond or not rule_cond["symbol_triggers"]:
            rule_cond["symbol_triggers"] = list(pred_cond.get("symbol_triggers", []))
        else:
            existing = set(rule_cond["symbol_triggers"])
            for st in pred_cond.get("symbol_triggers", []):
                if st not in existing:
                    rule_cond["symbol_triggers"].append(st)

        # Merge pattern regex
        if ("pattern" not in rule_cond or not rule_cond["pattern"]) and "pattern" in pred_cond:
            rule_cond["pattern"] = pred_cond["pattern"]

        return rule_dict

    def benchmark_loading_time(self, rule_dicts: list[dict[str, Any]]) -> dict[str, Any]:
        """Measures compile-time resolution latency over a list of rule dictionaries."""
        start = time.perf_counter()
        resolved_count = 0

        for r_dict in rule_dicts:
            if "uses" in r_dict:
                self.resolve_rule_dict(r_dict)
                resolved_count += 1

        elapsed_ms = (time.perf_counter() - start) * 1000
        return {
            "total_rules": len(rule_dicts),
            "resolved_predicates": resolved_count,
            "latency_ms": round(elapsed_ms, 3),
        }
