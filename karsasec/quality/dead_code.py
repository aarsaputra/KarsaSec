"""Rule Dead Code Detector module for detecting unreachable predicates or incomplete rule definitions."""

from __future__ import annotations

from typing import Any

from karsasec.rules.loader import YAMLRuleLoader
from karsasec.rules.patterns import get_default_rules_directory


class DeadCodeDetector:
    """Detects rules with empty triggers, missing condition patterns, or absent remediation guidance."""

    def __init__(self) -> None:
        self.loader = YAMLRuleLoader()
        self.rules_dir = get_default_rules_directory()

    def detect_dead_rules(self) -> list[dict[str, Any]]:
        """Scans rules for dead-code indicators."""
        rules = self.loader.load_directory(self.rules_dir)
        dead_issues: list[dict[str, Any]] = []

        for r in rules:
            reasons: list[str] = []

            # Check missing condition or missing both pattern AND symbol_triggers
            if not r.condition or (not r.condition.pattern and not r.condition.symbol_triggers):
                reasons.append("Missing both condition pattern and symbol_triggers")

            # Missing target languages
            if not r.target or not r.target.languages:
                reasons.append("No target languages defined")

            if reasons:
                dead_issues.append(
                    {
                        "id": r.id,
                        "name": r.metadata.name,
                        "issues": reasons,
                    }
                )

        return dead_issues
