"""Strict security policy boundary for AI Consumer layer (E13-1)."""

from __future__ import annotations

from enum import StrEnum


class AICapability(StrEnum):
    """Enumeration of AI capabilities and action permissions."""

    # Allowed read-only capabilities
    READ_FINDING = "READ_FINDING"
    READ_EVIDENCE = "READ_EVIDENCE"
    READ_SOURCE_SNIPPET = "READ_SOURCE_SNIPPET"
    READ_RULE_METADATA = "READ_RULE_METADATA"
    RETRIEVE_KNOWLEDGE = "RETRIEVE_KNOWLEDGE"
    GENERATE_EXPLANATION = "GENERATE_EXPLANATION"

    # Forbidden mutation & execution capabilities
    WRITE_SOURCE = "WRITE_SOURCE"
    WRITE_FINDING = "WRITE_FINDING"
    WRITE_VERDICT = "WRITE_VERDICT"
    CHANGE_SEVERITY = "CHANGE_SEVERITY"
    SUPPRESS_FINDING = "SUPPRESS_FINDING"
    EXECUTE_COMMAND = "EXECUTE_COMMAND"
    EXECUTE_CODE = "EXECUTE_CODE"
    READ_SECRETS = "READ_SECRETS"
    ARBITRARY_FILESYSTEM_ACCESS = "ARBITRARY_FILESYSTEM_ACCESS"
    OVERRIDE_SECURITY_DECISION = "OVERRIDE_SECURITY_DECISION"


class AIPolicyViolationError(PermissionError):
    """Raised when an AI operation attempts to violate trust boundaries or mutate security decisions."""


class AIPolicy:
    """Enforces strict read-only boundary preventing AI layer from mutating security state or executing code."""

    _ALLOWED_CAPABILITIES = {
        AICapability.READ_FINDING,
        AICapability.READ_EVIDENCE,
        AICapability.READ_SOURCE_SNIPPET,
        AICapability.READ_RULE_METADATA,
        AICapability.RETRIEVE_KNOWLEDGE,
        AICapability.GENERATE_EXPLANATION,
    }

    @classmethod
    def is_allowed(cls, capability: AICapability | str) -> bool:
        """Checks if a capability is permitted under the read-only policy."""
        try:
            cap_enum = AICapability(capability)
        except ValueError:
            return False
        return cap_enum in cls._ALLOWED_CAPABILITIES

    @classmethod
    def assert_allowed(cls, capability: AICapability | str) -> None:
        """Asserts that a capability is allowed; raises AIPolicyViolationError if forbidden."""
        if not cls.is_allowed(capability):
            raise AIPolicyViolationError(f"AIPolicy DENIED operation '{capability}'. AI Consumer layer is 100% READ-ONLY.")
