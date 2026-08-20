"""Authentication Provider Abstraction for KarsaSec REST API.

Resolves an HTTP request into an authenticated ``Principal``.  The provider
is a pluggable abstraction so that Sprint F4 can swap the implementation for
JWT / OAuth2 / OIDC without modifying routing code.

For Sprint F1 a simple ``HeaderAuthenticationProvider`` is supplied that
validates an ``X-API-Key`` header against a configured secret.
Raw credentials MUST NEVER be logged.
"""

from __future__ import annotations

import hmac
from abc import ABC, abstractmethod

from fastapi import HTTPException, Request, status

from karsasec.server.config import server_settings
from karsasec.server.security.models import ALL_PERMISSIONS, Principal


class AuthenticationError(Exception):
    """Raised when request authentication fails."""


class AuthenticationProvider(ABC):
    """Abstract authentication provider interface."""

    @abstractmethod
    def authenticate(self, request: Request) -> Principal:
        """Resolve the request into an authenticated Principal.

        Raises ``AuthenticationError`` when credentials are missing,
        malformed, expired, or otherwise invalid.
        """


class HeaderAuthenticationProvider(AuthenticationProvider):
    """Development/test authentication using ``X-API-Key`` header.

    Validates the presented key with constant-time comparison against the
    configured secret.  Raw key values are NEVER logged or included in
    error responses.
    """

    def __init__(self, secret_key: str | None = None) -> None:
        self._secret_key = secret_key or server_settings.auth_secret_key

    def authenticate(self, request: Request) -> Principal:
        """Authenticate via X-API-Key header."""
        key = request.headers.get("X-API-Key")
        if not key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required: missing X-API-Key header.",
            )

        if not hmac.compare_digest(key, self._secret_key):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication failed: invalid credentials.",
            )

        return Principal(
            identity="api-client",
            display_name="API Client",
            scopes=ALL_PERMISSIONS,
        )


# Default global provider instance (overridable via DI)
default_auth_provider = HeaderAuthenticationProvider()
