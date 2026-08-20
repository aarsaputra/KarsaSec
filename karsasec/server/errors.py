"""Privacy-Safe Centralized Error Handling for KarsaSec REST API."""

from __future__ import annotations

from fastapi import Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from karsasec.ai.remediation.rtp.errors import (
    RTPError,
    RTPPrivacyError,
    RTPValidationError,
)


class APIErrorDetail(BaseModel):
    """Detailed error info model."""

    code: str = Field(..., description="Machine-readable error code.")
    message: str = Field(..., description="Human-readable error summary.")
    details: list[str] = Field(default_factory=list, description="Optional details (privacy-safe).")


class APIErrorResponse(BaseModel):
    """Unified API error response payload."""

    error: APIErrorDetail
    request_id: str = Field(..., description="X-Request-ID correlation identifier.")


def build_error_response(
    status_code: int,
    code: str,
    message: str,
    request_id: str,
    details: list[str] | None = None,
) -> JSONResponse:
    """Constructs a privacy-safe JSONResponse with unified error schema."""
    payload = APIErrorResponse(
        error=APIErrorDetail(
            code=code,
            message=message,
            details=details or [],
        ),
        request_id=request_id,
    )
    return JSONResponse(status_code=status_code, content=payload.model_dump())


def get_request_id(request: Request) -> str:
    """Retrieve X-Request-ID from request state or headers."""
    return getattr(request.state, "request_id", request.headers.get("X-Request-ID", "unknown"))


async def rtp_validation_exception_handler(request: Request, exc: RTPValidationError) -> JSONResponse:
    """Handle RTP validation errors."""
    return build_error_response(
        status_code=status.HTTP_409_CONFLICT,
        code="RTP_VALIDATION_FAILED",
        message="Remediation transaction package validation failed.",
        request_id=get_request_id(request),
        details=[str(exc)],
    )


async def rtp_privacy_exception_handler(request: Request, exc: RTPPrivacyError) -> JSONResponse:
    """Handle RTP privacy boundary violations."""
    return build_error_response(
        status_code=status.HTTP_400_BAD_REQUEST,
        code="RTP_PRIVACY_VIOLATION",
        message="Transaction payload contains forbidden private fields.",
        request_id=get_request_id(request),
        details=[str(exc)],
    )


async def rtp_generic_exception_handler(request: Request, exc: RTPError) -> JSONResponse:
    """Handle generic RTP errors."""
    return build_error_response(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        code="RTP_ERROR",
        message="Remediation transaction error.",
        request_id=get_request_id(request),
        details=[str(exc)],
    )


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Handle Pydantic request validation errors cleanly."""
    err_msgs = [f"{'.'.join(str(loc) for loc in err['loc'])}: {err['msg']}" for err in exc.errors()]
    return build_error_response(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        code="VALIDATION_ERROR",
        message="Invalid request payload or query parameters.",
        request_id=get_request_id(request),
        details=err_msgs,
    )


async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Sanitized global 500 error handler avoiding internal stack trace leakage."""
    return build_error_response(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        code="INTERNAL_SERVER_ERROR",
        message="An internal server error occurred processing the request.",
        request_id=get_request_id(request),
        details=[],
    )
