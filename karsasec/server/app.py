"""FastAPI Application Factory for KarsaSec Enterprise REST API.

create_app() is the single entry point for constructing the FastAPI application.
It wires:
  - CORS middleware
  - X-Request-ID correlation middleware
  - Privacy-safe exception handlers
  - v1 API router under /api/v1

CAPABILITY AUDIT: Zero shell-invocation, system-call, or dynamic-eval primitives in this module.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware

from karsasec.ai.remediation.rtp.errors import (
    RTPError,
    RTPPrivacyError,
    RTPValidationError,
)
from karsasec.server.api.v1.router import v1_router
from karsasec.server.config import ServerSettings, server_settings
from karsasec.server.errors import (
    generic_exception_handler,
    rtp_generic_exception_handler,
    rtp_privacy_exception_handler,
    rtp_validation_exception_handler,
    validation_exception_handler,
)
from karsasec.server.middleware import RequestCorrelationMiddleware
from karsasec.utils.logging import logger


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan handler for startup/shutdown logging."""
    logger.info("KarsaSec Enterprise REST API starting up.")
    yield
    logger.info("KarsaSec Enterprise REST API shutting down.")


def create_app(settings: ServerSettings | None = None) -> FastAPI:
    """Construct and configure the KarsaSec FastAPI application.

    Returns a fully-configured FastAPI instance ready for ASGI serving.
    """
    cfg = settings or server_settings

    app = FastAPI(
        title=cfg.title,
        version=cfg.version,
        openapi_url=f"{cfg.api_prefix}/openapi.json",
        docs_url=f"{cfg.api_prefix}/docs",
        redoc_url=f"{cfg.api_prefix}/redoc",
        lifespan=_lifespan,
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    # X-Request-ID correlation
    app.add_middleware(RequestCorrelationMiddleware)

    # Privacy-safe exception handlers
    app.add_exception_handler(RTPValidationError, rtp_validation_exception_handler)  # type: ignore[arg-type]
    app.add_exception_handler(RTPPrivacyError, rtp_privacy_exception_handler)  # type: ignore[arg-type]
    app.add_exception_handler(RTPError, rtp_generic_exception_handler)  # type: ignore[arg-type]
    app.add_exception_handler(RequestValidationError, validation_exception_handler)  # type: ignore[arg-type]
    app.add_exception_handler(Exception, generic_exception_handler)

    # Mount v1 router
    app.include_router(v1_router, prefix=cfg.api_prefix)

    return app


# Default ASGI app instance
app = create_app()
