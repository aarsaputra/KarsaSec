"""Sprint E15 — Security Policy Engine.

Evaluates configurable security policies against vulnerability assessment metrics.
"""

from typing import Any

from karsasec.analysis.e15_models import DecisionStatus, SecurityPolicy


class SecurityPolicyEngine:
    """Deterministic security policy evaluation engine."""

    def __init__(self, default_policy: SecurityPolicy | None = None) -> None:
        self.default_policy = default_policy or SecurityPolicy(
            policy_id="POL-STRICT-DEFAULT",
            policy_version="1.0.0",
            minimum_priority="MEDIUM",
            minimum_confidence=0.70,
            allowed_regression_states=("RESOLVED", "NOT_TESTED"),
            require_valid_evidence=True,
            require_valid_exploitability=True,
            block_unknown=True,
            require_remediation_for_confirmed=True,
        )

    def evaluate_rule(
        self,
        policy: SecurityPolicy,
        rule_name: str,
        condition_met: bool,
        evaluated_rules: list[str],
        failed_rules: list[str],
    ) -> bool:
        """Evaluates a single policy rule and tracks rule history."""
        evaluated_rules.append(rule_name)
        if not condition_met:
            failed_rules.append(rule_name)
            return False
        return True

    def is_policy_valid(self, policy: SecurityPolicy) -> bool:
        """Validates policy schema and fields."""
        if policy is None or not isinstance(policy, SecurityPolicy):
            return False
        return policy.is_valid()
