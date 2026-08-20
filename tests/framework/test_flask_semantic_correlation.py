"""Unit and determinism test suite for Flask Semantic Correlation Engine (Sprint E10-3C)."""

from __future__ import annotations

import importlib
import inspect
import json

from karsasec.framework.diagnostics import ErrorCode, Severity
from karsasec.framework.framework_semantics.correlation import FlaskSemanticCorrelator
from karsasec.framework.intermediate import (
    AuthDefinition,
    ConfigDefinition,
    ControllerDefinition,
    HandlerDefinition,
    IntermediateSemanticRepresentation,
    MiddlewareDefinition,
    RouteDefinition,
)
from karsasec.framework.origin import OriginMetadata, SourceLocation
from karsasec.framework.semantic_models import SemanticEdgeType, SemanticNodeType


class TestArchitectureBoundary:
    """Phase 0: Enforce strict ISR-only input boundary."""

    def test_no_forbidden_imports_in_correlation_package(self):
        """Verify correlation package contains zero imports of ast, ast_adapter, or runtime execution modules."""
        correlation_modules = [
            "karsasec.framework.framework_semantics.correlation.contracts",
            "karsasec.framework.framework_semantics.correlation.identity",
            "karsasec.framework.framework_semantics.correlation.edge_identity",
            "karsasec.framework.framework_semantics.correlation.state",
            "karsasec.framework.framework_semantics.correlation.resolver",
            "karsasec.framework.framework_semantics.correlation.policy",
            "karsasec.framework.framework_semantics.correlation.route_correlator",
            "karsasec.framework.framework_semantics.correlation.controller_correlator",
            "karsasec.framework.framework_semantics.correlation.middleware_correlator",
            "karsasec.framework.framework_semantics.correlation.auth_correlator",
            "karsasec.framework.framework_semantics.correlation.config_correlator",
            "karsasec.framework.framework_semantics.correlation.diagnostics",
            "karsasec.framework.framework_semantics.correlation.graph_validator",
            "karsasec.framework.framework_semantics.correlation.normalizer",
            "karsasec.framework.framework_semantics.correlation.correlator",
        ]

        forbidden = ["ast", "ASTNodeWrapper", "ast_adapter", "subprocess", "eval", "exec"]

        for mod_name in correlation_modules:
            mod = importlib.import_module(mod_name)
            src = inspect.getsource(mod)

            # Check forbidden keywords
            for word in forbidden:
                assert f"import {word}" not in src, f"Forbidden import '{word}' in {mod_name}"
                assert f"from {word}" not in src, f"Forbidden import '{word}' in {mod_name}"


class TestRouteControllerHandlerCorrelation:
    """Test Route, Controller, and Handler correlation contracts."""

    def test_single_route_handler_correlation(self):
        """ROUTE -> HANDLER (HANDLES edge)."""
        loc = SourceLocation(file_path="app.py", line=10)
        route = RouteDefinition(
            path="/index", method="GET", handler="index", framework="FLASK", origin=OriginMetadata(location_info=loc)
        )
        handler = HandlerDefinition(
            name="index", function_name="index", framework="FLASK", origin=OriginMetadata(location_info=loc)
        )
        isr = IntermediateSemanticRepresentation(routes=(route,), handlers=(handler,))

        correlator = FlaskSemanticCorrelator()
        res = correlator.run(isr)

        assert res.is_valid is True
        graph = res.graph
        assert len(graph.nodes()) == 2
        assert len(graph.edges()) == 1

        edge = list(graph.edges())[0]
        assert edge.edge_type == SemanticEdgeType.HANDLES
        assert edge.attributes["handler_name"] == "index"

    def test_controller_declares_handler_correlation(self):
        """CONTROLLER -> HANDLER (DECLARES edge)."""
        loc = SourceLocation(file_path="views.py", line=15)
        ctrl = ControllerDefinition(
            name="UserView",
            class_name="UserView",
            handlers=("get_user",),
            framework="FLASK",
            origin=OriginMetadata(location_info=loc),
        )
        handler = HandlerDefinition(
            name="get_user", function_name="get_user", framework="FLASK", origin=OriginMetadata(location_info=loc)
        )
        isr = IntermediateSemanticRepresentation(controllers=(ctrl,), handlers=(handler,))

        correlator = FlaskSemanticCorrelator()
        res = correlator.run(isr)

        assert res.is_valid is True
        edges = list(res.graph.edges())
        assert len(edges) == 1
        assert edges[0].edge_type == SemanticEdgeType.DECLARES

    def test_missing_handler_emits_unresolved_diagnostic(self):
        """Missing handler target emits UNRESOLVED warning diagnostic."""
        loc = SourceLocation(file_path="app.py", line=10)
        route = RouteDefinition(
            path="/missing",
            method="GET",
            handler="non_existent",
            framework="FLASK",
            origin=OriginMetadata(location_info=loc),
        )
        isr = IntermediateSemanticRepresentation(routes=(route,))

        correlator = FlaskSemanticCorrelator()
        res = correlator.run(isr)

        assert res.is_valid is True
        assert len(res.graph.edges()) == 0
        assert len(res.diagnostics) == 1
        assert res.diagnostics[0].code == ErrorCode.MISSING_HANDLER
        assert res.diagnostics[0].severity == Severity.WARNING

    def test_ambiguous_handler_emits_diagnostic_and_early_stops(self):
        """Ambiguous handler matches emit AMBIGUOUS diagnostic and zero edges."""
        loc1 = SourceLocation(file_path="app1.py", line=10)
        loc2 = SourceLocation(file_path="app2.py", line=20)
        route = RouteDefinition(
            path="/ambiguous",
            method="GET",
            handler="login",
            framework="FLASK",
            origin=OriginMetadata(location_info=loc1),
        )
        h1 = HandlerDefinition(
            name="login", function_name="login", framework="FLASK", origin=OriginMetadata(location_info=loc1)
        )
        h2 = HandlerDefinition(
            name="login", function_name="login", framework="FLASK", origin=OriginMetadata(location_info=loc2)
        )
        isr = IntermediateSemanticRepresentation(routes=(route,), handlers=(h1, h2))

        correlator = FlaskSemanticCorrelator()
        res = correlator.run(isr)

        assert len(res.graph.edges()) == 0
        ambig_diags = [d for d in res.diagnostics if d.code == ErrorCode.AMBIGUOUS_CONTROLLER]
        assert len(ambig_diags) == 1
        assert ambig_diags[0].severity == Severity.WARNING


class TestMiddlewareCorrelation:
    """Test Middleware propagation policies."""

    def test_global_middleware_propagation(self):
        """Global middleware propagates to all routes with inherited propagation."""
        loc = SourceLocation(file_path="mw.py", line=5)
        mw = MiddlewareDefinition(
            name="logger", scope="global", confidence=0.9, framework="FLASK", origin=OriginMetadata(location_info=loc)
        )
        r1 = RouteDefinition(
            path="/r1", method="GET", handler="h1", framework="FLASK", origin=OriginMetadata(location_info=loc)
        )
        r2 = RouteDefinition(
            path="/r2", method="POST", handler="h2", framework="FLASK", origin=OriginMetadata(location_info=loc)
        )
        isr = IntermediateSemanticRepresentation(middlewares=(mw,), routes=(r1, r2))

        correlator = FlaskSemanticCorrelator()
        res = correlator.run(isr)

        mw_edges = [e for e in res.graph.edges() if e.edge_type == SemanticEdgeType.PROTECTS]
        assert len(mw_edges) == 2
        for edge in mw_edges:
            assert edge.attributes["scope"] == "global"
            assert edge.attributes["propagation"] == "inherited"
            assert edge.attributes["confidence"] == 0.9

    def test_route_specific_middleware_propagation(self):
        """Route-specific middleware matches targeted route path."""
        loc = SourceLocation(file_path="mw.py", line=5)
        mw = MiddlewareDefinition(
            name="auth_mw",
            scope="route",
            target_routes=("/admin",),
            framework="FLASK",
            origin=OriginMetadata(location_info=loc),
        )
        r1 = RouteDefinition(
            path="/admin", method="GET", handler="admin_h", framework="FLASK", origin=OriginMetadata(location_info=loc)
        )
        r2 = RouteDefinition(
            path="/public",
            method="GET",
            handler="public_h",
            framework="FLASK",
            origin=OriginMetadata(location_info=loc),
        )
        isr = IntermediateSemanticRepresentation(middlewares=(mw,), routes=(r1, r2))

        correlator = FlaskSemanticCorrelator()
        res = correlator.run(isr)

        mw_edges = [e for e in res.graph.edges() if e.edge_type == SemanticEdgeType.PROTECTS]
        assert len(mw_edges) == 1
        assert mw_edges[0].attributes["scope"] == "route"
        assert mw_edges[0].attributes["propagation"] == "direct"


class TestAuthAndConfigCorrelation:
    """Test Auth and Config correlation policies."""

    def test_auth_handler_and_route_protection(self):
        """AUTH -> HANDLER and AUTH -> ROUTE (PROTECTS edge)."""
        loc = SourceLocation(file_path="auth.py", line=10)
        auth = AuthDefinition(
            auth_type="JWT",
            provider="jwt_manager",
            handler="login_fn",
            protected_routes=("/api/*",),
            roles=("admin",),
            framework="FLASK",
            origin=OriginMetadata(location_info=loc),
        )
        handler = HandlerDefinition(
            name="login_fn", function_name="login_fn", framework="FLASK", origin=OriginMetadata(location_info=loc)
        )
        route = RouteDefinition(
            path="/api/data",
            method="GET",
            handler="data_fn",
            framework="FLASK",
            origin=OriginMetadata(location_info=loc),
        )
        isr = IntermediateSemanticRepresentation(auths=(auth,), handlers=(handler,), routes=(route,))

        correlator = FlaskSemanticCorrelator()
        res = correlator.run(isr)

        auth_edges = [e for e in res.graph.edges() if e.edge_type == SemanticEdgeType.PROTECTS]
        assert len(auth_edges) == 2

    def test_standalone_config_nodes_without_synthetic_application_node(self):
        """Config nodes emitted as standalone CONFIG nodes (zero synthetic nodes)."""
        loc = SourceLocation(file_path="config.py", line=1)
        cfg = ConfigDefinition(
            key="SECRET_KEY", value="super-secret", framework="FLASK", origin=OriginMetadata(location_info=loc)
        )
        isr = IntermediateSemanticRepresentation(configs=(cfg,))

        correlator = FlaskSemanticCorrelator()
        res = correlator.run(isr)

        nodes = list(res.graph.nodes())
        assert len(nodes) == 1
        assert nodes[0].node_type == SemanticNodeType.CONFIG
        assert len(res.graph.edges()) == 0


class TestOrphansAndInvariants:
    """Test Orphan diagnostics and Graph Invariant checks."""

    def test_orphan_handler_emits_info_diagnostic_and_valid_graph(self):
        """Unlinked handler emits ORPHAN_HANDLER diagnostic with Severity.INFO; is_valid remains True."""
        loc = SourceLocation(file_path="app.py", line=10)
        handler = HandlerDefinition(
            name="standalone_fn",
            function_name="standalone_fn",
            framework="FLASK",
            origin=OriginMetadata(location_info=loc),
        )
        isr = IntermediateSemanticRepresentation(handlers=(handler,))

        correlator = FlaskSemanticCorrelator()
        res = correlator.run(isr)

        assert res.is_valid is True
        orphan_diags = [d for d in res.diagnostics if d.code == ErrorCode.ORPHAN_HANDLER]
        assert len(orphan_diags) == 1
        assert orphan_diags[0].severity == Severity.INFO


class TestDeterminismAndIdempotency:
    """Verify 10x repeated execution and shuffled-input order invariance."""

    def test_10x_repeated_execution_byte_for_byte_determinism(self):
        """Same ISR input executed 10x sequentially produces 100% byte-for-byte identical serialized graph JSON."""
        loc = SourceLocation(file_path="app.py", line=10)
        route = RouteDefinition(
            path="/user", method="GET", handler="get_user", framework="FLASK", origin=OriginMetadata(location_info=loc)
        )
        handler = HandlerDefinition(
            name="get_user", function_name="get_user", framework="FLASK", origin=OriginMetadata(location_info=loc)
        )
        mw = MiddlewareDefinition(
            name="auth_mw", scope="global", framework="FLASK", origin=OriginMetadata(location_info=loc)
        )
        auth = AuthDefinition(
            auth_type="Session",
            provider="flask_login",
            handler="get_user",
            framework="FLASK",
            origin=OriginMetadata(location_info=loc),
        )
        cfg = ConfigDefinition(key="DEBUG", value=True, framework="FLASK", origin=OriginMetadata(location_info=loc))

        isr = IntermediateSemanticRepresentation(
            routes=(route,), handlers=(handler,), middlewares=(mw,), auths=(auth,), configs=(cfg,)
        )

        correlator = FlaskSemanticCorrelator()

        first_res = correlator.run(isr)
        first_json = json.dumps(first_res.graph.to_dict(), sort_keys=True)

        for _ in range(9):
            repeat_res = correlator.run(isr)
            repeat_json = json.dumps(repeat_res.graph.to_dict(), sort_keys=True)
            assert repeat_json == first_json

    def test_shuffled_input_ordering_invariance(self):
        """Changing input definition tuple ordering produces 100% byte-for-byte identical serialized graph JSON."""
        loc1 = SourceLocation(file_path="a.py", line=1)
        loc2 = SourceLocation(file_path="b.py", line=2)
        loc3 = SourceLocation(file_path="c.py", line=3)

        r1 = RouteDefinition(
            path="/a", method="GET", handler="ha", framework="FLASK", origin=OriginMetadata(location_info=loc1)
        )
        r2 = RouteDefinition(
            path="/b", method="GET", handler="hb", framework="FLASK", origin=OriginMetadata(location_info=loc2)
        )
        r3 = RouteDefinition(
            path="/c", method="GET", handler="hc", framework="FLASK", origin=OriginMetadata(location_info=loc3)
        )

        h1 = HandlerDefinition(
            name="ha", function_name="ha", framework="FLASK", origin=OriginMetadata(location_info=loc1)
        )
        h2 = HandlerDefinition(
            name="hb", function_name="hb", framework="FLASK", origin=OriginMetadata(location_info=loc2)
        )
        h3 = HandlerDefinition(
            name="hc", function_name="hc", framework="FLASK", origin=OriginMetadata(location_info=loc3)
        )

        isr_original = IntermediateSemanticRepresentation(routes=(r1, r2, r3), handlers=(h1, h2, h3))

        # Shuffled tuples
        isr_shuffled = IntermediateSemanticRepresentation(routes=(r3, r1, r2), handlers=(h2, h3, h1))

        correlator = FlaskSemanticCorrelator()

        orig_json = json.dumps(correlator.run(isr_original).graph.to_dict(), sort_keys=True)
        shuffled_json = json.dumps(correlator.run(isr_shuffled).graph.to_dict(), sort_keys=True)

        assert orig_json == shuffled_json
