"""Rule Validator checking YAML structure and schema before compilation."""

from __future__ import annotations

from typing import Any


class RuleValidationError(Exception):
    """Exception raised when rule validation fails."""

    pass


class RuleValidator:
    """Pre-compilation validator for security rules."""

    def validate(self, rule_data: dict[str, Any]) -> None:
        if not isinstance(rule_data, dict):
            raise RuleValidationError("Rule data must be a dictionary.")

        if "id" not in rule_data:
            raise RuleValidationError("Rule missing required field: 'id'")

        if "severity" not in rule_data:
            raise RuleValidationError("Rule missing required field: 'severity'")

        if "pattern" not in rule_data and "patterns" not in rule_data and "query" not in rule_data:
            raise RuleValidationError("Rule must contain at least one pattern, patterns array, or query definition.")
