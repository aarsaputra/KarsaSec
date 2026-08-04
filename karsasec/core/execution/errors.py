"""Execution exception hierarchy for KarsaSec Rule Engine."""

from karsasec.core.finding.errors import EvidenceUnavailableError

class ExecutionError(Exception):
    """Base exception for all rule execution pipeline failures."""
    pass

class RuleError(ExecutionError):
    """Raised when an individual rule evaluation encounters an unhandled runtime error."""
    pass

__all__ = [
    "ExecutionError",
    "RuleError",
    "EvidenceUnavailableError",
]
