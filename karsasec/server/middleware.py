"""ASGI Middleware for Request Correlation and Security Headers."""

from __future__ import annotations

import time
import uuid
from collections.abc import Awaitable, Callable
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from karsasec.utils.logging import logger

SENSITIVE_HEADERS = {"authorization", "proxy-authorization", "x-api-key", "cookie", "set-cookie"}


class RequestCorrelationMiddleware(BaseHTTPMiddleware):
    """Ensures X-Request-ID header exists, attaches it to request state, and logs request lifecycle safely."""

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        req_id = request.headers.get("X-Request-ID")
        if not req_id or not req_id.strip():
            req_id = f"req-{uuid.uuid4().hex[:12]}"

        request.state.request_id = req_id
        start_time = time.perf_counter()

        # Execute downstream handlers
        response = await call_next(request)

        duration_ms = (time.perf_counter() - start_time) * 1000.0
        response.headers["X-Request-ID"] = req_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"

        logger.debug(
            f"API Request processed: method={request.method} path={request.url.path} "
            f"status={response.status_code} duration_ms={duration_ms:.2f} request_id={req_id}"
        )
        return response
