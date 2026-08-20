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
    DUP_MIDDLEWARE = "ERR_SEM_DUP_MIDDLEWARE"
    UNKNOWN_EXTENSION = "ERR_SEM_UNKNOWN_EXTENSION"
    INVALID_MIDDLEWARE_HANDLER = "ERR_SEM_INVALID_MIDDLEWARE_HANDLER"
    DUP_CONTROLLER = "ERR_SEM_DUP_CONTROLLER"
    ORPHAN_HANDLER = "ERR_SEM_ORPHAN_HANDLER"
    DUP_CONFIG_KEY = "ERR_SEM_DUP_CONFIG_KEY"
    UNKNOWN_CONFIG_SOURCE = "ERR_SEM_UNKNOWN_CONFIG_SOURCE"
    INVALID_CONFIG_CLASS = "ERR_SEM_INVALID_CONFIG_CLASS"
    CONFIG_OVERRIDE = "ERR_SEM_CONFIG_OVERRIDE"
    CONFIG_CLASS_NOT_FOUND = "ERR_SEM_CONFIG_CLASS_NOT_FOUND"
    ENV_VARIABLE_NOT_FOUND = "ERR_SEM_ENV_VARIABLE_NOT_FOUND"
    DUP_CONFIG_ASSIGNMENT = "ERR_SEM_DUP_CONFIG_ASSIGNMENT"
    MISSING_SECRET_KEY = "ERR_SEM_MISSING_SECRET_KEY"
    INVALID_CONFIG_VALUE = "ERR_SEM_INVALID_CONFIG_VALUE"
    UNSUPPORTED_CONFIG = "ERR_SEM_UNSUPPORTED_CONFIG"
    WEAK_SECRET_KEY = "ERR_SEM_WEAK_SECRET_KEY"
    DANGEROUS_CONFIG = "ERR_SEM_DANGEROUS_CONFIG"
    UNKNOWN_AUTH_PROVIDER = "ERR_SEM_UNKNOWN_AUTH_PROVIDER"
    INVALID_AUTH_HANDLER = "ERR_SEM_INVALID_AUTH_HANDLER"
    INVALID_ROLE = "ERR_SEM_INVALID_ROLE"
    INVALID_PERMISSION = "ERR_SEM_INVALID_PERMISSION"
    DUP_AUTH_POLICY = "ERR_SEM_DUP_AUTH_POLICY"
    MISSING_AUTH_MANAGER = "ERR_SEM_MISSING_AUTH_MANAGER"
    UNKNOWN_AUTH_SCHEME = "ERR_SEM_UNKNOWN_AUTH_SCHEME"
    UNRESOLVED_AUTH_DECORATOR = "ERR_SEM_UNRESOLVED_AUTH_DECORATOR"
    DUP_AUTH_MANAGER = "ERR_SEM_DUP_AUTH_MANAGER"
    GENERIC_VALIDATION_ERROR = "ERR_SEM_GENERIC_VALIDATION"
    # Correlation Engine Diagnostics (Sprint E10-3C)
    ORPHAN_ROUTE = "ERR_SEM_ORPHAN_ROUTE"
    ORPHAN_CONTROLLER = "ERR_SEM_ORPHAN_CONTROLLER"
    UNRESOLVED_BLUEPRINT = "ERR_SEM_UNRESOLVED_BLUEPRINT"
    UNRESOLVED_AUTH_BINDING = "ERR_SEM_UNRESOLVED_AUTH_BINDING"
    AMBIGUOUS_CONTROLLER = "ERR_SEM_AMBIGUOUS_CONTROLLER"
    AMBIGUOUS_MIDDLEWARE_SCOPE = "ERR_SEM_AMBIGUOUS_MIDDLEWARE_SCOPE"
    DUPLICATE_SEMANTIC_EDGE = "ERR_SEM_DUPLICATE_SEMANTIC_EDGE"
    INVALID_GRAPH_INVARIANT = "ERR_SEM_INVALID_GRAPH_INVARIANT"


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
