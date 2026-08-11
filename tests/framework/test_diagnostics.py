"""Unit tests for compiler-style diagnostics and ErrorCode serialization."""

from __future__ import annotations

from karsasec.framework.diagnostics import ErrorCode, SemanticDiagnostic, Severity
from karsasec.framework.origin import SourceLocation


def test_error_code_enum_values():
    assert ErrorCode.DUP_MIDDLEWARE == "ERR_SEM_DUP_MIDDLEWARE"
    assert ErrorCode.UNKNOWN_EXTENSION == "ERR_SEM_UNKNOWN_EXTENSION"
    assert ErrorCode.INVALID_MIDDLEWARE_HANDLER == "ERR_SEM_INVALID_MIDDLEWARE_HANDLER"


def test_semantic_diagnostic_serialization():
    loc = SourceLocation(file_path="app.py", line=15, column=4)
    diag = SemanticDiagnostic(
        code=ErrorCode.DUP_MIDDLEWARE,
        severity=Severity.ERROR,
        message="Duplicate before_request middleware registered",
        location=loc,
        evidence="@app.before_request",
        remediation="Remove duplicate middleware hook",
    )
    d = diag.to_dict()
    assert d["code"] == "ERR_SEM_DUP_MIDDLEWARE"
    assert d["severity"] == "ERROR"
    assert d["location"]["file_path"] == "app.py"

    restored = SemanticDiagnostic.from_dict(d)
    assert restored.code == ErrorCode.DUP_MIDDLEWARE
    assert restored.severity == Severity.ERROR
    assert restored.location.line == 15
    assert restored.evidence == "@app.before_request"
