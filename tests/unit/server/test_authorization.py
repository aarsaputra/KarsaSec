"""Unit tests for karsasec.server.security.authorization."""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from karsasec.server.security.authorization import authorize
from karsasec.server.security.models import Permission, Principal


class TestAuthorize:
    def test_authorize_passes_when_permission_present(self):
        principal = Principal(identity="user", scopes=frozenset({Permission.SCAN_READ}))
        # Should not raise
        authorize(principal, Permission.SCAN_READ)

    def test_authorize_raises_403_when_scope_missing(self):
        principal = Principal(identity="readonly", scopes=frozenset({Permission.SCAN_READ}))
        with pytest.raises(HTTPException) as exc_info:
            authorize(principal, Permission.SCAN_CREATE)
        assert exc_info.value.status_code == 403

    def test_authorize_error_message_contains_scope(self):
        principal = Principal(identity="readonly", scopes=frozenset())
        with pytest.raises(HTTPException) as exc_info:
            authorize(principal, Permission.REMEDIATION_CREATE)
        assert "remediation:create" in str(exc_info.value.detail)

    def test_authorize_error_contains_identity(self):
        principal = Principal(identity="alice", scopes=frozenset())
        with pytest.raises(HTTPException) as exc_info:
            authorize(principal, Permission.RECEIPT_READ)
        assert "alice" in str(exc_info.value.detail)

    def test_authorize_all_permissions_passes_all_scopes(self):
        from karsasec.server.security.models import ALL_PERMISSIONS

        principal = Principal(identity="admin", scopes=ALL_PERMISSIONS)
        for perm in Permission:
            authorize(principal, perm)  # Must not raise
