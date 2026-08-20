"""Security Principal and Permission Models for KarsaSec REST API.

Defines the identity and authorization scope primitives used by the
authentication and authorization boundaries.  These models are transport-agnostic
and carry no HTTP / FastAPI dependency.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Permission(str, Enum):
    """Enumerated API permission scopes."""

    SCAN_READ = "scan:read"
    SCAN_CREATE = "scan:create"
    FINDING_READ = "finding:read"
    REMEDIATION_CREATE = "remediation:create"
    REMEDIATION_READ = "remediation:read"
    RECEIPT_READ = "receipt:read"


# Default scope set for a fully-authorised development principal.
ALL_PERMISSIONS: frozenset[Permission] = frozenset(Permission)


@dataclass(frozen=True, slots=True)
class Principal:
    """Authenticated identity resolved by the authentication boundary.

    Attributes:
        identity: Unique identifier for the principal (e.g. username or API key ID).
        display_name: Human-readable label, never used for security decisions.
        scopes: Set of granted permission scopes.
        tenant_id: Optional multi-tenant identifier (reserved for Sprint F4).
    """

    identity: str
    display_name: str = ""
    scopes: frozenset[Permission] = field(default_factory=lambda: ALL_PERMISSIONS)
    tenant_id: str | None = None

    def has_permission(self, permission: Permission) -> bool:
        """Return True when the principal holds the given permission."""
        return permission in self.scopes
