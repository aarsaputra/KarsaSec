"""Unit tests for AIPolicy trust boundary enforcement (E13-1)."""

from __future__ import annotations

import pytest

from karsasec.ai.explainer.policy import AICapability, AIPolicy, AIPolicyViolationError


def test_policy_allowed_capabilities() -> None:
    allowed = [
        AICapability.READ_FINDING,
        AICapability.READ_EVIDENCE,
        AICapability.READ_SOURCE_SNIPPET,
        AICapability.READ_RULE_METADATA,
        AICapability.RETRIEVE_KNOWLEDGE,
        AICapability.GENERATE_EXPLANATION,
    ]
    for cap in allowed:
        assert AIPolicy.is_allowed(cap) is True
        AIPolicy.assert_allowed(cap)  # Should not raise exception


def test_policy_denied_capabilities() -> None:
    denied = [
        AICapability.WRITE_SOURCE,
        AICapability.WRITE_FINDING,
        AICapability.WRITE_VERDICT,
        AICapability.CHANGE_SEVERITY,
        AICapability.SUPPRESS_FINDING,
        AICapability.EXECUTE_COMMAND,
        AICapability.EXECUTE_CODE,
        AICapability.READ_SECRETS,
        AICapability.ARBITRARY_FILESYSTEM_ACCESS,
        AICapability.OVERRIDE_SECURITY_DECISION,
    ]
    for cap in denied:
        assert AIPolicy.is_allowed(cap) is False
        with pytest.raises(AIPolicyViolationError) as exc_info:
            AIPolicy.assert_allowed(cap)
        assert "AIPolicy DENIED operation" in str(exc_info.value)
        assert "100% READ-ONLY" in str(exc_info.value)


def test_policy_invalid_string_denied() -> None:
    assert AIPolicy.is_allowed("INVALID_CUSTOM_ACTION") is False
    with pytest.raises(AIPolicyViolationError):
        AIPolicy.assert_allowed("INVALID_CUSTOM_ACTION")
