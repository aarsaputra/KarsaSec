"""Authorization Engine for KarsaSec REST API.

Enforces scope-based permission checks BEFORE service invocation.
Authorization is strictly separate from authentication: the
``AuthenticationProvider`` resolves *who* the caller is, while
``authorize`` decides *whether* they may perform a given action.
"""

from __future__ import annotations

from fastapi import HTTPException, status

from karsasec.server.security.models import Permission, Principal


def authorize(principal: Principal, required: Permission) -> None:
    """Enforce that *principal* holds *required* permission.

    Raises ``HTTPException(403)`` when the scope is missing.

    This function intentionally returns ``None`` so that it can be called
    as a guard at the top of every route handler:

        authorize(principal, Permission.SCAN_CREATE)
    """
    if not principal.has_permission(required):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Forbidden: principal '{principal.identity}' lacks scope '{required.value}'.",
        )
