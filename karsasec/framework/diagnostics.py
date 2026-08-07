"""Compiler-style diagnostic models for Framework Semantic Validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from karsasec.framework.origin import SourceLocation


class Severity(StrEnum):
    """Diagnostic severity levels."""
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"


class ErrorCode(StrEnum):
    """Compiler-style error codes for semantic validation diagnostics."""
    DUP_ROUTE = "ERR_SEM_DUP_ROUTE"
    DUP_HANDLER = "ERR_SEM_DUP_HANDLER"
    MISSING_HANDLER = "ERR_SEM_MISSING_HANDLER"
    MISSING_CONTROLLER = "ERR_SEM_MISSING_CONTROLLER"
    ORPHAN_MIDDLEWARE = "ERR_SEM_ORPHAN_MIDDLEWARE"
    DUP_MODEL = "ERR_SEM_DUP_MODEL"
    BROKEN_DEP = "ERR_SEM_BROKEN_DEP"
    UNKNOWN_AUTH = "ERR_SEM_UNKNOWN_AUTH"
    GENERIC_VALIDATION_ERROR = "ERR_SEM_GENERIC_VALIDATION"


@dataclass(frozen=True)
class SemanticDiagnostic:
    """Compiler-style diagnostic emitted during ISR validation or semantic processing."""
    code: ErrorCode
    severity: Severity
    message: str
    location: SourceLocation = field(default_factory=SourceLocation)
    evidence: str = ""
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code.value,
            "severity": self.severity.value,
            "message": self.message,
            "location": self.location.to_dict(),
            "evidence": self.evidence,
            "remediation": self.remediation,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SemanticDiagnostic:
        return cls(
            code=ErrorCode(data["code"]),
            severity=Severity(data.get("severity", "ERROR")),
            message=data.get("message", ""),
            location=SourceLocation.from_dict(data.get("location", {})),
            evidence=data.get("evidence", ""),
            remediation=data.get("remediation", ""),
        )
