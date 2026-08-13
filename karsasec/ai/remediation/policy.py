"""Remediation Safety Policy Enforcer (Sprint E13-3).

Enforces Security Invariants G12-G14:
  - Fails closed on any attempt to write source files, execute subprocesses, or perform git operations.
  - Prohibits altering SecurityVerdict status or suppressing findings.
"""

from __future__ import annotations

from enum import StrEnum


class RemediationCapabilityViolationError(PermissionError):
    """Raised when an operation violates the read-only / proposal-only security policy."""


class RemediationCapability(StrEnum):
    """Allowed and prohibited capabilities in the remediation subsystem."""

    # Allowed Read-Only Capabilities
    READ_SOURCE = "READ_SOURCE"
    READ_EVIDENCE = "READ_EVIDENCE"
    READ_RAG = "READ_RAG"
    GENERATE_PLAN = "GENERATE_PLAN"
    GENERATE_PROPOSAL = "GENERATE_PROPOSAL"
    VALIDATE_PROPOSAL = "VALIDATE_PROPOSAL"

    # Prohibited Mutation Capabilities
    WRITE_SOURCE = "WRITE_SOURCE"
    APPLY_PATCH = "APPLY_PATCH"
    EXECUTE_COMMAND = "EXECUTE_COMMAND"
    GIT_COMMIT = "GIT_COMMIT"
    GIT_PUSH = "GIT_PUSH"
    DELETE_FILE = "DELETE_FILE"
    MODIFY_VERDICT = "MODIFY_VERDICT"
    SUPPRESS_FINDING = "SUPPRESS_FINDING"


class RemediationPolicy:
    """Policy enforcer guaranteeing read-only, non-mutating behavior for remediation planning."""

    _ALLOWED_CAPABILITIES = frozenset({
        RemediationCapability.READ_SOURCE,
        RemediationCapability.READ_EVIDENCE,
        RemediationCapability.READ_RAG,
        RemediationCapability.GENERATE_PLAN,
        RemediationCapability.GENERATE_PROPOSAL,
        RemediationCapability.VALIDATE_PROPOSAL,
    })

    _PROHIBITED_CAPABILITIES = frozenset({
        RemediationCapability.WRITE_SOURCE,
        RemediationCapability.APPLY_PATCH,
        RemediationCapability.EXECUTE_COMMAND,
        RemediationCapability.GIT_COMMIT,
        RemediationCapability.GIT_PUSH,
        RemediationCapability.DELETE_FILE,
        RemediationCapability.MODIFY_VERDICT,
        RemediationCapability.SUPPRESS_FINDING,
    })

    @classmethod
    def is_allowed(cls, capability: RemediationCapability | str) -> bool:
        """Check if a capability is allowed by policy."""
        try:
            cap = RemediationCapability(capability)
        except ValueError:
            return False
        return cap in cls._ALLOWED_CAPABILITIES and cap not in cls._PROHIBITED_CAPABILITIES

    @classmethod
    def assert_allowed(cls, capability: RemediationCapability | str) -> None:
        """Assert that a capability is allowed, raising an error if prohibited or unknown."""
        if not cls.is_allowed(capability):
            raise RemediationCapabilityViolationError(
                f"Remediation policy violation: capability '{capability}' is strictly prohibited by security invariants G12-G14."
            )
