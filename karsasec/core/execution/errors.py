"""Execution error hierarchy for scanner resilience and boundary protection."""

class ExecutionError(Exception):
    """Base exception for scanner execution errors."""
    pass

class RuleError(ExecutionError):
    """Exception raised when a Rule definition or evaluation fails."""
    pass

class EvidenceUnavailableError(ExecutionError):
    """Exception raised when mandatory source_bytes is missing or invalid."""
    pass
