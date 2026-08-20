"""Unit tests for karsasec.server.security.models."""

from __future__ import annotations

import pytest

from karsasec.server.security.models import ALL_PERMISSIONS, Permission, Principal


class TestPermission:
    def test_permission_values_are_strings(self):
        for perm in Permission:
            assert ":" in perm.value

    def test_all_permissions_is_complete(self):
        assert ALL_PERMISSIONS == frozenset(Permission)


class TestPrincipal:
    def test_has_permission_returns_true_for_granted_scope(self):
        p = Principal(identity="user1", scopes=frozenset({Permission.SCAN_READ}))
        assert p.has_permission(Permission.SCAN_READ) is True

    def test_has_permission_returns_false_for_missing_scope(self):
        p = Principal(identity="user1", scopes=frozenset({Permission.SCAN_READ}))
        assert p.has_permission(Permission.SCAN_CREATE) is False

    def test_principal_is_immutable(self):
        p = Principal(identity="user1")
        with pytest.raises((AttributeError, TypeError)):
            p.identity = "hacked"  # type: ignore[misc]

    def test_default_scopes_contain_all_permissions(self):
        p = Principal(identity="admin")
        assert p.scopes == ALL_PERMISSIONS

    def test_tenant_id_defaults_to_none(self):
        p = Principal(identity="x")
        assert p.tenant_id is None
