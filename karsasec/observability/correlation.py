"""ContextVar Correlation and Traceability Propagation Manager for Sprint F6.

Provides contextvars-backed correlation, request, and operation context handling across
asyncio tasks, thread pools, and worker execution boundaries.
"""

from __future__ import annotations

import uuid
from contextlib import contextmanager
from contextvars import ContextVar, Token
from collections.abc import Generator

# Context variables with thread-safe & async-safe context inheritance
correlation_id_var: ContextVar[str | None] = ContextVar("correlation_id", default=None)
request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)
operation_id_var: ContextVar[str | None] = ContextVar("operation_id", default=None)


def generate_correlation_id(prefix: str = "corr") -> str:
    """Generate a unique correlation ID."""
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def get_correlation_id() -> str | None:
    """Retrieve active correlation_id from context."""
    return correlation_id_var.get()


def set_correlation_id(cid: str | None) -> Token[str | None]:
    """Set active correlation_id in context."""
    return correlation_id_var.set(cid)


def get_request_id() -> str | None:
    """Retrieve active request_id from context."""
    return request_id_var.get()


def set_request_id(rid: str | None) -> Token[str | None]:
    """Set active request_id in context."""
    return request_id_var.set(rid)


def get_operation_id() -> str | None:
    """Retrieve active operation_id from context."""
    return operation_id_var.get()


def set_operation_id(oid: str | None) -> Token[str | None]:
    """Set active operation_id in context."""
    return operation_id_var.set(oid)


@contextmanager
def correlation_scope(
    correlation_id: str | None = None,
    request_id: str | None = None,
    operation_id: str | None = None,
) -> Generator[str, None, None]:
    """Context manager for setting correlation attributes within a block scope.

    Yields:
        Active correlation_id string.
    """
    cid = correlation_id or get_correlation_id() or generate_correlation_id()
    rid = request_id or get_request_id()
    oid = operation_id or get_operation_id()

    token_cid = correlation_id_var.set(cid)
    token_rid = request_id_var.set(rid)
    token_oid = operation_id_var.set(oid)

    try:
        yield cid
    finally:
        correlation_id_var.reset(token_cid)
        request_id_var.reset(token_rid)
        operation_id_var.reset(token_oid)
