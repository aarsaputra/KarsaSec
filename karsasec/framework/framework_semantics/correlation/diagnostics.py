"""Correlation diagnostics helper module for Sprint E10-3C."""

from __future__ import annotations

from karsasec.framework.diagnostics import ErrorCode, SemanticDiagnostic, Severity
from karsasec.framework.origin import SourceLocation


def create_orphan_diagnostic(
    code: ErrorCode,
    entity_name: str,
    location: SourceLocation | None = None,
    evidence: str = "",
) -> SemanticDiagnostic:
    """Create an ORPHAN diagnostic with Severity.INFO."""
    return SemanticDiagnostic(
        code=code,
        severity=Severity.INFO,
        message=f"Entity '{entity_name}' is orphaned (not bound to any route or parent container).",
        location=location or SourceLocation(),
        evidence=evidence,
        remediation="Verify if entity is intentionally registered dynamically or unlinked.",
    )


def create_unresolved_diagnostic(
    code: ErrorCode,
    target_name: str,
    location: SourceLocation | None = None,
    evidence: str = "",
) -> SemanticDiagnostic:
    """Create an UNRESOLVED diagnostic with Severity.WARNING."""
    return SemanticDiagnostic(
        code=code,
        severity=Severity.WARNING,
        message=f"Unresolved semantic target relationship for '{target_name}'.",
        location=location or SourceLocation(),
        evidence=evidence,
        remediation="Check target definition or import qualified name.",
    )


def create_ambiguous_diagnostic(
    code: ErrorCode,
    target_name: str,
    candidate_count: int,
    location: SourceLocation | None = None,
    evidence: str = "",
) -> SemanticDiagnostic:
    """Create an AMBIGUOUS diagnostic with Severity.WARNING."""
    return SemanticDiagnostic(
        code=code,
        severity=Severity.WARNING,
        message=f"Ambiguous semantic relationship target for '{target_name}' ({candidate_count} matching candidates found).",
        location=location or SourceLocation(),
        evidence=evidence,
        remediation="Use fully qualified symbol names to disambiguate target binding.",
    )


def create_invariant_diagnostic(
    message: str,
    evidence: str = "",
) -> SemanticDiagnostic:
    """Create a Graph Invariant Violation diagnostic with Severity.ERROR."""
    return SemanticDiagnostic(
        code=ErrorCode.INVALID_GRAPH_INVARIANT,
        severity=Severity.ERROR,
        message=f"Graph invariant violation: {message}",
        location=SourceLocation(),
        evidence=evidence,
        remediation="Ensure graph nodes and edges comply with canonical structural contracts.",
    )
