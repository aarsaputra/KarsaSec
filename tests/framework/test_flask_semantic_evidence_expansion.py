"""Unit tests for Sprint E10-3E Flask Semantic Evidence Expansion contracts."""

from __future__ import annotations

from karsasec.framework.factories import FrameworkNodeFactory
from karsasec.framework.intermediate import AuthDefinition, ConfigDefinition, RouteDefinition


def test_route_definition_evidence_defaults():
    """Verify route evidence defaults to UNKNOWN for absence of evidence."""
    r = RouteDefinition(path="/user", method="GET", handler="get_user")
    assert r.sensitivity == "UNKNOWN"
    assert r.exposure == "UNKNOWN"

    node = FrameworkNodeFactory.create_route_node(r)
    assert node.attributes["sensitivity"] == "UNKNOWN"
    assert node.attributes["exposure"] == "UNKNOWN"


def test_route_definition_explicit_sensitivity_and_exposure():
    """Verify route sensitivity and exposure are propagated when explicitly provided."""
    r = RouteDefinition(
        path="/admin/delete",
        method="POST",
        handler="delete_admin",
        sensitivity="HIGH",
        exposure="INTERNAL",
    )
    assert r.sensitivity == "HIGH"
    assert r.exposure == "INTERNAL"

    node = FrameworkNodeFactory.create_route_node(r)
    assert node.attributes["sensitivity"] == "HIGH"
    assert node.attributes["exposure"] == "INTERNAL"


def test_auth_definition_evidence_defaults():
    """Verify auth evidence defaults to UNKNOWN for absence of evidence."""
    a = AuthDefinition(auth_type="JWT", provider="custom")
    assert a.auth_strength == "UNKNOWN"
    assert a.mechanism == "UNKNOWN"
    assert a.jwt_algorithm is None

    node = FrameworkNodeFactory.create_auth_node(a)
    assert node.attributes["auth_strength"] == "UNKNOWN"
    assert node.attributes["mechanism"] == "UNKNOWN"
    assert node.attributes["jwt_algorithm"] is None


def test_auth_definition_explicit_evidence():
    """Verify explicit auth mechanism, auth strength, and jwt algorithm."""
    a = AuthDefinition(
        auth_type="JWT",
        provider="flask-jwt-extended",
        auth_strength="WEAK",
        mechanism="JWT",
        jwt_algorithm="none",
    )
    assert a.auth_strength == "WEAK"
    assert a.mechanism == "JWT"
    assert a.jwt_algorithm == "none"

    node = FrameworkNodeFactory.create_auth_node(a)
    assert node.attributes["auth_strength"] == "WEAK"
    assert node.attributes["mechanism"] == "JWT"
    assert node.attributes["jwt_algorithm"] == "none"


def test_config_definition_evidence_defaults():
    """Verify config provenance defaults to UNKNOWN / assignment."""
    c = ConfigDefinition(key="DEBUG", value=True)
    assert c.source_kind == "unknown"
    assert c.provenance_type == "assignment"
    assert c.environment == "UNKNOWN"

    node = FrameworkNodeFactory.create_config_node(c)
    assert node.attributes["source_kind"] == "unknown"
    assert node.attributes["provenance_type"] == "assignment"
    assert node.attributes["environment"] == "UNKNOWN"
    assert node.attributes["value"] is True


def test_config_definition_explicit_provenance_and_environment():
    """Verify explicit configuration provenance and environment propagation."""
    c = ConfigDefinition(
        key="DEBUG",
        value=True,
        source_kind="literal",
        provenance_type="assignment",
        environment="PRODUCTION",
    )
    assert c.source_kind == "literal"
    assert c.provenance_type == "assignment"
    assert c.environment == "PRODUCTION"

    node = FrameworkNodeFactory.create_config_node(c)
    assert node.attributes["source_kind"] == "literal"
    assert node.attributes["provenance_type"] == "assignment"
    assert node.attributes["environment"] == "PRODUCTION"
    assert node.attributes["value"] is True
