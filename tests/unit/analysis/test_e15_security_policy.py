"""Unit tests for Security Policy Engine."""

import pytest

from karsasec.analysis.e15_models import SecurityPolicy
from karsasec.analysis.e15_security_policy import SecurityPolicyEngine


def test_default_policy_validity():
    engine = SecurityPolicyEngine()
    assert engine.is_policy_valid(engine.default_policy) is True


def test_invalid_policy_detection():
    engine = SecurityPolicyEngine()
    bad_policy = SecurityPolicy(
        policy_id="",
        policy_version="1.0.0",
        minimum_priority="HIGH",
        minimum_confidence=float("nan"),
        allowed_regression_states=(),
        require_valid_evidence=True,
        require_valid_exploitability=True,
        block_unknown=True,
        require_remediation_for_confirmed=True,
    )
    assert engine.is_policy_valid(bad_policy) is False
