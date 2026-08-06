"""Rule Conflict & Overlap Detector for identifying redundant or overlapping detection patterns."""

from __future__ import annotations

from typing import Any

from karsasec.rules.loader import YAMLRuleLoader
from karsasec.rules.patterns import get_default_rules_directory


class ConflictDetector:
    """Scans rule repository for pattern overlaps, duplicate names, and conflicting metadata."""

    def __init__(self) -> None:
        self.loader = YAMLRuleLoader()
        self.rules_dir = get_default_rules_directory()

    def detect_conflicts(self) -> dict[str, list[dict[str, Any]]]:
        """Analyzes all active rules for potential overlaps and structural conflicts."""
        rules = self.loader.load_directory(self.rules_dir)

        duplicates: list[dict[str, Any]] = []
        pattern_overlaps: list[dict[str, Any]] = []

        seen_patterns: dict[str, str] = {}
        seen_names: dict[str, str] = {}

        for r in rules:
            # Check identical regex patterns
            if r.condition and r.condition.pattern:
                pat = r.condition.pattern.strip()
                if pat in seen_patterns:
                    pattern_overlaps.append({
                        "rule_a": seen_patterns[pat],
                        "rule_b": r.id,
                        "pattern": pat,
                    })
                else:
                    seen_patterns[pat] = r.id

            # Check duplicate rule names
            name = r.metadata.name.strip().lower()
            if name in seen_names:
                duplicates.append({
                    "rule_a": seen_names[name],
                    "rule_b": r.id,
                    "name": r.metadata.name,
                })
            else:
                seen_names[name] = r.id

        return {
            "duplicate_names": duplicates,
            "pattern_overlaps": pattern_overlaps,
        }
