"""Unit tests for Framework Semantic Core Foundation (Sprint E10-2A)."""

import pytest

from karsasec.framework.intermediate import (
    AuthDefinition,
    ConfigDefinition,
    ControllerDefinition,
    DependencyDefinition,
    HandlerDefinition,
    IntermediateSemanticRepresentation,
    MiddlewareDefinition,
    ModelDefinition,
    ORMDefinition,
    RouteDefinition,
    ServiceDefinition,
    TemplateDefinition,
)
from karsasec.framework.origin import (
    Confidence,
    Evidence,
    ExtractorInfo,
    OriginMetadata,
    SourceLocation,
)
from karsasec.framework.semantic_models import (
    FrameworkSemanticEdge,
    FrameworkSemanticGraph,
    FrameworkSemanticNode,
    SemanticEdgeType,
    SemanticNodeType,
)
from karsasec.framework.semantic_registry import SemanticRegistry
from karsasec.framework.symbol_table import SemanticSymbolTable, SymbolBinding

# ============================================================================
# 1. Semantic Models & FrameworkSemanticGraph Tests
# ============================================================================

def test_semantic_node_immutability():
    origin = OriginMetadata(reason_str="Test node")
    node = FrameworkSemanticNode(
        id="node_1",
        node_type=SemanticNodeType.ROUTE,
        name="/api/v1/users",
        language="Python",
        cpg_node_id="cpg_101",
        origin=origin,
    )
    assert node.id == "node_1"
    assert node.node_type == SemanticNodeType.ROUTE
    assert node.name == "/api/v1/users"
    assert node.origin.reason() == "Test node"

    with pytest.raises(AttributeError):
        node.name = "/api/v2/users"  # type: ignore


def test_semantic_edge_immutability():
    edge = FrameworkSemanticEdge(
        source_id="route_1",
        target_id="handler_1",
        edge_type=SemanticEdgeType.HANDLES,
    )
    assert edge.source_id == "route_1"
    assert edge.target_id == "handler_1"
    assert edge.edge_type == SemanticEdgeType.HANDLES

    with pytest.raises(AttributeError):
        edge.source_id = "route_2"  # type: ignore


def test_graph_add_and_remove_node():
    graph = FrameworkSemanticGraph()
    n1 = FrameworkSemanticNode(id="n1", node_type=SemanticNodeType.ROUTE, name="/login")
    n2 = FrameworkSemanticNode(id="n2", node_type=SemanticNodeType.HANDLER, name="login_handler")

    g2 = graph.add_node(n1).add_node(n2)
    assert len(g2.nodes()) == 2
    assert g2.node("n1") == n1

    g3 = g2.remove_node("n1")
    assert len(g3.nodes()) == 1
    assert g3.node("n1") is None
    assert g3.node("n2") == n2


def test_graph_add_and_remove_edge():
    g = FrameworkSemanticGraph()
    n1 = FrameworkSemanticNode(id="n1", node_type=SemanticNodeType.ROUTE, name="/login")
    n2 = FrameworkSemanticNode(id="n2", node_type=SemanticNodeType.HANDLER, name="login_handler")
    e1 = FrameworkSemanticEdge(source_id="n1", target_id="n2", edge_type=SemanticEdgeType.HANDLES)

    g2 = g.add_node(n1).add_node(n2).add_edge(e1)
    assert len(g2.edges()) == 1
    assert g2.edge("n1", "n2") == e1

    g3 = g2.remove_edge("n1", "n2")
    assert len(g3.edges()) == 0


def test_graph_filter_and_find():
    g = FrameworkSemanticGraph()
    n1 = FrameworkSemanticNode(id="n1", node_type=SemanticNodeType.ROUTE, name="/a")
    n2 = FrameworkSemanticNode(id="n2", node_type=SemanticNodeType.ROUTE, name="/b")
    n3 = FrameworkSemanticNode(id="n3", node_type=SemanticNodeType.MIDDLEWARE, name="auth_mw")
    g = g.add_node(n1).add_node(n2).add_node(n3)

    routes = g.filter(SemanticNodeType.ROUTE)
    assert len(routes) == 2
    assert {r.id for r in routes} == {"n1", "n2"}

    found = g.find(lambda n: n.name.startswith("/a"))
    assert len(found) == 1
    assert found[0].id == "n1"


def test_graph_statistics():
    g = FrameworkSemanticGraph()
    n1 = FrameworkSemanticNode(id="n1", node_type=SemanticNodeType.ROUTE, name="/a")
    n2 = FrameworkSemanticNode(id="n2", node_type=SemanticNodeType.HANDLER, name="h1")
    e1 = FrameworkSemanticEdge(source_id="n1", target_id="n2", edge_type=SemanticEdgeType.HANDLES)
    g = g.add_node(n1).add_node(n2).add_edge(e1)

    stats = g.statistics()
    assert stats["node_count"] == 2
    assert stats["edge_count"] == 1
    assert stats["node_types"]["ROUTE"] == 1
    assert stats["node_types"]["HANDLER"] == 1
    assert stats["edge_types"]["HANDLES"] == 1


def test_graph_json_serialization():
    g = FrameworkSemanticGraph()
    n1 = FrameworkSemanticNode(id="n1", node_type=SemanticNodeType.ROUTE, name="/users")
    n2 = FrameworkSemanticNode(id="n2", node_type=SemanticNodeType.HANDLER, name="get_users")
    e1 = FrameworkSemanticEdge(source_id="n1", target_id="n2", edge_type=SemanticEdgeType.HANDLES)
    g = g.add_node(n1).add_node(n2).add_edge(e1)

    json_str = g.to_json()
    g_deserialized = FrameworkSemanticGraph.from_json(json_str)

    assert len(g_deserialized.nodes()) == 2
    assert len(g_deserialized.edges()) == 1
    assert g_deserialized.node("n1").name == "/users"
    assert g_deserialized.edge("n1", "n2").edge_type == SemanticEdgeType.HANDLES


def test_graph_deterministic_ordering():
    g = FrameworkSemanticGraph()
    g = g.add_node(FrameworkSemanticNode(id="z_node", node_type=SemanticNodeType.ROUTE, name="z"))
    g = g.add_node(FrameworkSemanticNode(id="a_node", node_type=SemanticNodeType.ROUTE, name="a"))

    nodes = g.nodes()
    assert nodes[0].id == "a_node"
    assert nodes[1].id == "z_node"


# ============================================================================
# 2. Provenance & OriginMetadata Tests
# ============================================================================

def test_source_location_dict_roundtrip():
    loc = SourceLocation(file_path="app.py", line=10, column=5, end_line=10, end_column=20)
    data = loc.to_dict()
    loc2 = SourceLocation.from_dict(data)
    assert loc == loc2


def test_evidence_dict_roundtrip():
    ev = Evidence(snippet="@app.route('/login')", rule_or_marker="FlaskRouteDecorator", file_path="app.py", line=15)
    data = ev.to_dict()
    ev2 = Evidence.from_dict(data)
    assert ev == ev2


def test_extractor_info_dict_roundtrip():
    info = ExtractorInfo(extractor_name="FlaskRouteExtractor", version="1.2.0", framework="FLASK")
    data = info.to_dict()
    info2 = ExtractorInfo.from_dict(data)
    assert info == info2


def test_origin_metadata_apis():
    loc = SourceLocation(file_path="routes/auth.py", line=42)
    ev = Evidence(snippet="@router.post('/login')", rule_or_marker="FastAPIRoute", file_path="routes/auth.py", line=42)
    info = ExtractorInfo(extractor_name="FastAPIExtractor", version="2.0.0", framework="FASTAPI")

    origin = OriginMetadata(
        extractor_info=info,
        location_info=loc,
        confidence=Confidence.CONFIDENT,
        reason_str="Detected FastAPI route decorator",
        evidence_list=(ev,),
        parser_name="TreeSitterPython",
        framework_name="FASTAPI",
    )

    assert origin.reason() == "Detected FastAPI route decorator"
    assert origin.location().file_path == "routes/auth.py"
    assert origin.evidence()[0].snippet == "@router.post('/login')"
    explain_str = origin.explain()
    assert "FastAPIExtractor" in explain_str
    assert "routes/auth.py:42" in explain_str


def test_origin_metadata_json_serialization():
    origin = OriginMetadata(
        reason_str="Flask app instantiation",
        confidence=Confidence.LIKELY,
        framework_name="FLASK",
    )
    data = origin.to_dict()
    origin2 = OriginMetadata.from_dict(data)
    assert origin2.reason() == "Flask app instantiation"
    assert origin2.confidence == Confidence.LIKELY


# ============================================================================
# 3. Intermediate Semantic Representation (ISR) Tests
# ============================================================================

def test_route_definition_immutability_and_serialization():
    r = RouteDefinition(path="/items", method="GET", handler="list_items", framework="FLASK")
    assert r.path == "/items"
    assert r.method == "GET"

    data = r.to_dict()
    r2 = RouteDefinition.from_dict(data)
    assert r == r2


def test_middleware_definition():
    m = MiddlewareDefinition(name="AuthMiddleware", scope="route", order=1, target_routes=("/admin",))
    assert m.name == "AuthMiddleware"
    assert m.target_routes == ("/admin",)
    assert MiddlewareDefinition.from_dict(m.to_dict()) == m


def test_controller_definition():
    c = ControllerDefinition(name="UserController", class_name="UserControllerClass", handlers=("index", "show"))
    assert c.name == "UserController"
    assert len(c.handlers) == 2
    assert ControllerDefinition.from_dict(c.to_dict()) == c


def test_handler_definition():
    h = HandlerDefinition(name="get_user", function_name="get_user_fn", parameters=("user_id",), return_type="User")
    assert h.name == "get_user"
    assert h.return_type == "User"
    assert HandlerDefinition.from_dict(h.to_dict()) == h


def test_service_definition():
    s = ServiceDefinition(name="PaymentService", service_type="payment", methods=("charge", "refund"))
    assert s.name == "PaymentService"
    assert ServiceDefinition.from_dict(s.to_dict()) == s


def test_model_definition():
    m = ModelDefinition(model_name="User", table_name="users", fields=("id", "email"), relations=("orders",))
    assert m.model_name == "User"
    assert ModelDefinition.from_dict(m.to_dict()) == m


def test_orm_definition():
    m = ModelDefinition(model_name="Product", table_name="products", fields=("id", "price"))
    orm = ORMDefinition(orm_name="SQLAlchemy", models=(m,), query_methods=("filter_by", "all"))
    assert orm.orm_name == "SQLAlchemy"
    assert len(orm.models) == 1
    assert ORMDefinition.from_dict(orm.to_dict()) == orm


def test_auth_definition():
    a = AuthDefinition(auth_type="OAuth2", protected_routes=("/api/v1/private",), roles_or_scopes=("admin",))
    assert a.auth_type == "OAuth2"
    assert AuthDefinition.from_dict(a.to_dict()) == a


def test_config_definition():
    cfg = ConfigDefinition(key="SECRET_KEY", value="supersecret", is_sensitive=True)
    assert cfg.key == "SECRET_KEY"
    assert cfg.is_sensitive is True
    assert ConfigDefinition.from_dict(cfg.to_dict()) == cfg


def test_template_definition():
    t = TemplateDefinition(template_name="index.html", engine="Jinja2", is_autoescape=True)
    assert t.template_name == "index.html"
    assert TemplateDefinition.from_dict(t.to_dict()) == t


def test_dependency_definition():
    d = DependencyDefinition(dependency_name="db_session", target_class_or_fn="get_db", provider="FastAPIDepends")
    assert d.dependency_name == "db_session"
    assert DependencyDefinition.from_dict(d.to_dict()) == d


def test_isr_container_full_roundtrip():
    route = RouteDefinition(path="/login", method="POST", handler="login_fn")
    mw = MiddlewareDefinition(name="CorsMiddleware")
    ctrl = ControllerDefinition(name="AuthController")
    handler = HandlerDefinition(name="login_fn", function_name="login_fn")
    service = ServiceDefinition(name="AuthService")
    model = ModelDefinition(model_name="User")
    orm = ORMDefinition(orm_name="DjangoORM", models=(model,))
    auth = AuthDefinition(auth_type="Session")
    config = ConfigDefinition(key="DEBUG", value=True)
    template = TemplateDefinition(template_name="login.html")
    dep = DependencyDefinition(dependency_name="auth_provider", target_class_or_fn="AuthProvider")

    isr = IntermediateSemanticRepresentation(
        routes=(route,),
        middlewares=(mw,),
        controllers=(ctrl,),
        handlers=(handler,),
        services=(service,),
        orms=(orm,),
        models=(model,),
        auths=(auth,),
        configs=(config,),
        templates=(template,),
        dependencies=(dep,),
    )

    json_str = isr.to_json()
    isr2 = IntermediateSemanticRepresentation.from_json(json_str)

    assert len(isr2.routes) == 1
    assert isr2.routes[0].path == "/login"
    assert len(isr2.middlewares) == 1
    assert isr2.middlewares[0].name == "CorsMiddleware"
    assert len(isr2.controllers) == 1
    assert isr2.controllers[0].name == "AuthController"
    assert len(isr2.handlers) == 1
    assert len(isr2.services) == 1
    assert len(isr2.orms) == 1
    assert len(isr2.models) == 1
    assert len(isr2.auths) == 1
    assert len(isr2.configs) == 1
    assert len(isr2.templates) == 1
    assert len(isr2.dependencies) == 1


# ============================================================================
# 4. SemanticRegistry Tests
# ============================================================================

def test_registry_add_and_lookup():
    reg = SemanticRegistry()
    route = RouteDefinition(path="/api/data", method="GET", handler="get_data", cpg_ref="cpg_999")

    reg.add("route_1", route)
    assert reg.lookup("route_1") == route
    assert reg.lookup_route("/api/data") == route
    assert reg.lookup_cpg("cpg_999") == route


def test_registry_handler_and_controller_indexing():
    reg = SemanticRegistry()
    handler = HandlerDefinition(name="process_item", function_name="process_item")
    ctrl = ControllerDefinition(name="ItemController")

    reg.add("h1", handler)
    reg.add("c1", ctrl)

    assert reg.lookup_handler("process_item") == handler
    assert reg.lookup_controller("ItemController") == ctrl


def test_registry_file_indexing():
    reg = SemanticRegistry()
    loc = SourceLocation(file_path="app/views.py", line=12)
    origin = OriginMetadata(location_info=loc)
    route = RouteDefinition(path="/home", method="GET", handler="home", origin=origin)

    reg.add("r_home", route)
    items = reg.lookup_file("app/views.py")
    assert len(items) == 1
    assert items[0] == route


def test_registry_remove_and_replace():
    reg = SemanticRegistry()
    r1 = RouteDefinition(path="/v1", method="GET", handler="v1_h")
    r2 = RouteDefinition(path="/v2", method="GET", handler="v2_h")

    reg.add("r1", r1)
    assert reg.lookup_route("/v1") == r1

    reg.replace("r1", r2)
    assert reg.lookup_route("/v1") is None
    assert reg.lookup_route("/v2") == r2

    res = reg.remove("r1")
    assert res is True
    assert reg.lookup("r1") is None


def test_registry_merge():
    r1 = SemanticRegistry()
    r2 = SemanticRegistry()

    route1 = RouteDefinition(path="/r1", method="GET", handler="h1")
    route2 = RouteDefinition(path="/r2", method="POST", handler="h2")

    r1.add("id1", route1)
    r2.add("id2", route2)

    r1.merge(r2)
    assert r1.lookup("id1") == route1
    assert r1.lookup("id2") == route2
    assert r1.lookup_route("/r2") == route2


# ============================================================================
# 5. SemanticSymbolTable Tests
# ============================================================================

def test_symbol_table_forward_resolution():
    sym_table = SemanticSymbolTable()
    binding = SymbolBinding(
        symbol_path="route:/users -> handler:get_users -> controller:UserController",
        route_path="/users",
        handler_name="get_users",
        controller_name="UserController",
        cpg_node_id="cpg_fn_404",
    )

    sym_table.add_binding(binding)
    resolved = sym_table.resolve("route:/users -> handler:get_users -> controller:UserController")
    assert resolved == "cpg_fn_404"


def test_symbol_table_reverse_lookup():
    sym_table = SemanticSymbolTable()
    b1 = SymbolBinding(symbol_path="sym1", cpg_node_id="cpg_target")
    b2 = SymbolBinding(symbol_path="sym2", cpg_node_id="cpg_target")

    sym_table.add_binding(b1)
    sym_table.add_binding(b2)

    rev = sym_table.reverse_lookup("cpg_target")
    assert len(rev) == 2
    assert {b.symbol_path for b in rev} == {"sym1", "sym2"}


def test_symbol_table_definition_and_references():
    sym_table = SemanticSymbolTable()
    binding = SymbolBinding(
        symbol_path="handler:delete_account",
        route_path="/account/delete",
        handler_name="delete_account",
        cpg_node_id="cpg_del_fn",
    )
    sym_table.add_binding(binding)

    def_by_route = sym_table.definition("/account/delete")
    assert def_by_route == binding

    def_by_handler = sym_table.definition("delete_account")
    assert def_by_handler == binding

    refs = sym_table.references("cpg_del_fn")
    assert len(refs) == 1
    assert refs[0] == binding


def test_symbol_table_clear():
    sym_table = SemanticSymbolTable()
    b = SymbolBinding(symbol_path="s1", cpg_node_id="cpg1")
    sym_table.add_binding(b)
    assert sym_table.resolve("s1") == "cpg1"

    sym_table.clear()
    assert sym_table.resolve("s1") is None
    assert len(sym_table.reverse_lookup("cpg1")) == 0


def test_symbol_binding_to_dict():
    b = SymbolBinding(
        symbol_path="path/to/sym",
        route_path="/login",
        handler_name="login",
        controller_name="AuthCtrl",
        class_name="AuthCtrlClass",
        function_name="login_fn",
        cpg_node_id="node_123",
        metadata={"priority": 1},
    )
    d = b.to_dict()
    assert d["symbol_path"] == "path/to/sym"
    assert d["route_path"] == "/login"
    assert d["metadata"] == {"priority": 1}


def test_graph_node_labels_and_attributes():
    node = FrameworkSemanticNode(
        id="node_labels",
        node_type=SemanticNodeType.CONTROLLER,
        name="MainController",
        labels=("API", "Protected"),
        attributes={"auth_required": True},
    )
    d = node.to_dict()
    assert d["labels"] == ["API", "Protected"]
    assert d["attributes"]["auth_required"] is True

    node2 = FrameworkSemanticNode.from_dict(d)
    assert node2.labels == ("API", "Protected")
    assert node2.attributes == {"auth_required": True}


def test_graph_edge_attributes():
    edge = FrameworkSemanticEdge(
        source_id="n1",
        target_id="n2",
        edge_type=SemanticEdgeType.CALLS,
        attributes={"async": True},
    )
    d = edge.to_dict()
    assert d["attributes"]["async"] is True
    edge2 = FrameworkSemanticEdge.from_dict(d)
    assert edge2.attributes == {"async": True}


def test_graph_remove_nonexistent_node():
    g = FrameworkSemanticGraph()
    n1 = FrameworkSemanticNode(id="n1", node_type=SemanticNodeType.ROUTE, name="/test")
    g2 = g.add_node(n1)
    g3 = g2.remove_node("non_existent_id")
    assert g3 == g2


def test_graph_remove_nonexistent_edge():
    g = FrameworkSemanticGraph()
    n1 = FrameworkSemanticNode(id="n1", node_type=SemanticNodeType.ROUTE, name="/test")
    g2 = g.add_node(n1)
    g3 = g2.remove_edge("n1", "n2")
    assert len(g3.edges()) == 0


def test_registry_clear():
    reg = SemanticRegistry()
    reg.add("r1", RouteDefinition(path="/r1", method="GET", handler="h1"))
    assert reg.lookup("r1") is not None
    reg.clear()
    assert reg.lookup("r1") is None
    assert reg.lookup_route("/r1") is None


def test_registry_lookup_nonexistent():
    reg = SemanticRegistry()
    assert reg.lookup("unknown") is None
    assert reg.lookup_route("/unknown") is None
    assert reg.lookup_handler("unknown") is None
    assert reg.lookup_controller("unknown") is None
    assert reg.lookup_file("unknown.py") == []
    assert reg.lookup_cpg("cpg_unknown") is None


def test_symbol_table_definition_lookup_none():
    st = SemanticSymbolTable()
    assert st.definition("non_existent_symbol") is None


def test_default_global_singletons():
    from karsasec.framework import semantic_registry, semantic_symbol_table
    assert isinstance(semantic_registry, SemanticRegistry)
    assert isinstance(semantic_symbol_table, SemanticSymbolTable)

