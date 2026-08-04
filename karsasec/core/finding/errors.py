"""Exception definitions for Finding and Evidence collection."""

class FindingError(Exception):
    """Base exception for finding generation failures."""
    pass

class EvidenceUnavailableError(FindingError):
    """Raised when source_bytes or source code is missing during evidence extraction."""
    pass
