"""Unit tests for Framework Semantic Graph Engine (Sprint E10-2C)."""

import pytest

from karsasec.framework import (
    AuthDefinition,
    BuilderContext,
    BuilderOptions,
    ConfigDefinition,
    ControllerDefinition,
    Evidence,
    FrameworkEdgeFactory,
    FrameworkGraphBuilder,
    FrameworkGraphIntegrityChecker,
    FrameworkGraphOptimizer,
    FrameworkGraphSerializer,
    FrameworkGraphSnapshot,
    FrameworkNodeFactory,
    FrameworkSemanticEdge,
    FrameworkSemanticGraph,
    FrameworkSemanticNode,
    GraphFrozenError,
    GraphStatistics,
    HandlerDefinition,
    IntermediateSemanticRepresentation,
    MiddlewareDefinition,
    ModelDefinition,
    OriginMetadata,
    RouteDefinition,
    SemanticDiagnostic,
    SemanticEdgeType,
    SemanticNodeType,
    SerializationError,
    SourceLocation,
    TemplateDefinition,
    generate_semantic_node_id,
)


# Helper fixtures for standard ISR definitions
@pytest.fixture
def sample_location():
    return SourceLocation(file_path="app.py", line=15)


@pytest.fixture
def sample_origin(sample_location):
    return OriginMetadata(location_info=sample_location, evidence_list=(Evidence(snippet="def login(): pass"),))


@pytest.fixture
def sample_route(sample_origin):
    return RouteDefinition(
        path="/api/login",
        method="POST",
        handler="login_handler",
        framework="FLASK",
        language="Python",
        origin=sample_origin,
    )


@pytest.fixture
def sample_handler(sample_origin):
    return HandlerDefinition(
        name="login_handler",
        function_name="login_handler",
        parameters=("request",),
        framework="FLASK",
        language="Python",
        origin=sample_origin,
    )


@pytest.fixture
def sample_controller(sample_origin):
    return ControllerDefinition(
        name="AuthCtrl",
        class_name="AuthController",
        handlers=("login_handler",),
        framework="FLASK",
        language="Python",
        origin=sample_origin,
    )


@pytest.fixture
def sample_middleware(sample_origin):
    return MiddlewareDefinition(
        name="AuthMw",
        scope="route",
        target_routes=("/api/login",),
        framework="FLASK",
        language="Python",
        origin=sample_origin,
    )


@pytest.fixture
def sample_model(sample_origin):
    return ModelDefinition(
        model_name="User",
        table_name="users",
        fields=("id", "username"),
        framework="FLASK",
        language="Python",
        origin=sample_origin,
    )


@pytest.fixture
def sample_config(sample_origin):
    return ConfigDefinition(
        key="SECRET_KEY",
        value="supersecret",
        is_sensitive=True,
        framework="FLASK",
        language="Python",
        origin=sample_origin,
    )


@pytest.fixture
def sample_template(sample_origin):
    return TemplateDefinition(
        template_name="index.html",
        engine="jinja2",
        framework="FLASK",
        language="Python",
        origin=sample_origin,
    )


@pytest.fixture
def sample_auth(sample_origin):
    return AuthDefinition(
        auth_type="JWT",
        protected_routes=("/api/login",),
        framework="FLASK",
        language="Python",
        origin=sample_origin,
    )


@pytest.fixture
def sample_isr(
    sample_route,
    sample_handler,
    sample_controller,
    sample_middleware,
    sample_model,
    sample_config,
    sample_template,
    sample_auth,
):
    return IntermediateSemanticRepresentation(
        routes=(sample_route,),
        handlers=(sample_handler,),
        controllers=(sample_controller,),
        middlewares=(sample_middleware,),
        models=(sample_model,),
        configs=(sample_config,),
        templates=(sample_template,),
        auths=(sample_auth,),
    )


# ============================================================================
# 1. Deterministic ID Generator Tests (1-8)
# ============================================================================


def test_id_generator_determinism():
    id1 = generate_semantic_node_id("FLASK", "route", "POST /login", "app.py", 10)
    id2 = generate_semantic_node_id("FLASK", "route", "POST /login", "app.py", 10)
    assert id1 == id2
    assert len(id1) == 64  # SHA-256 length


def test_id_generator_case_insensitivity_for_framework_and_type():
    id1 = generate_semantic_node_id("flask", "route", "POST /login", "app.py", 10)
    id2 = generate_semantic_node_id("FLASK", "ROUTE", "POST /login", "app.py", 10)
    assert id1 == id2


def test_id_generator_different_inputs_produce_different_ids():
    id1 = generate_semantic_node_id("FLASK", "route", "POST /login", "app.py", 10)
    id2 = generate_semantic_node_id("FLASK", "route", "GET /login", "app.py", 10)
    id3 = generate_semantic_node_id("FASTAPI", "route", "POST /login", "app.py", 10)
    assert id1 != id2
    assert id1 != id3


def test_id_generator_empty_file_path():
    id_gen = generate_semantic_node_id("FLASK", "config", "DB_URI")
    assert len(id_gen) == 64


def test_id_generator_different_lines():
    id1 = generate_semantic_node_id("FLASK", "handler", "login", "app.py", 1)
    id2 = generate_semantic_node_id("FLASK", "handler", "login", "app.py", 2)
    assert id1 != id2


def test_id_generator_special_characters():
    id_gen = generate_semantic_node_id("EXPRESS", "route", "GET /api/v1/users/:id", "index.js", 42)
    assert isinstance(id_gen, str)
    assert len(id_gen) == 64


def test_id_generator_returns_hex():
    id_gen = generate_semantic_node_id("DJANGO", "model", "User", "models.py", 5)
    int(id_gen, 16)  # Should not raise ValueError


def test_id_generator_repeatability_across_instances():
    id1 = generate_semantic_node_id("SPRING", "controller", "UserController", "UserController.java", 15)
    id2 = generate_semantic_node_id("SPRING", "controller", "UserController", "UserController.java", 15)
    assert id1 == id2


# ============================================================================
# 2. Node & Edge Factory Tests (9-20)
# ============================================================================


def test_node_factory_create_route_node(sample_route):
    node = FrameworkNodeFactory.create_route_node(sample_route)
    assert node.node_type == SemanticNodeType.ROUTE
    assert node.name == "POST /api/login"
    assert node.attributes["method"] == "POST"
    assert node.attributes["path"] == "/api/login"
    assert "ROUTE" in node.labels


def test_node_factory_create_controller_node(sample_controller):
    node = FrameworkNodeFactory.create_controller_node(sample_controller)
    assert node.node_type == SemanticNodeType.CONTROLLER
    assert node.name == "AuthCtrl"
    assert node.attributes["class_name"] == "AuthController"


def test_node_factory_create_handler_node(sample_handler):
    node = FrameworkNodeFactory.create_handler_node(sample_handler)
    assert node.node_type == SemanticNodeType.HANDLER
    assert node.name == "login_handler"
    assert node.attributes["function_name"] == "login_handler"


def test_node_factory_create_middleware_node(sample_middleware):
    node = FrameworkNodeFactory.create_middleware_node(sample_middleware)
    assert node.node_type == SemanticNodeType.MIDDLEWARE
    assert node.name == "AuthMw"
    assert node.attributes["scope"] == "route"


def test_node_factory_create_model_node(sample_model):
    node = FrameworkNodeFactory.create_model_node(sample_model)
    assert node.node_type == SemanticNodeType.MODEL
    assert node.name == "User"
    assert node.attributes["table_name"] == "users"


def test_node_factory_create_config_node(sample_config):
    node = FrameworkNodeFactory.create_config_node(sample_config)
    assert node.node_type == SemanticNodeType.CONFIG
    assert node.name == "SECRET_KEY"
    assert node.attributes["is_sensitive"] is True


def test_node_factory_create_template_node(sample_template):
    node = FrameworkNodeFactory.create_template_node(sample_template)
    assert node.node_type == SemanticNodeType.TEMPLATE
    assert node.name == "index.html"
    assert node.attributes["engine"] == "jinja2"


def test_node_factory_create_auth_node(sample_auth):
    node = FrameworkNodeFactory.create_auth_node(sample_auth)
    assert node.node_type == SemanticNodeType.AUTH
    assert node.name == "JWT"
    assert node.attributes["auth_type"] == "JWT"


def test_edge_factory_create_edge_with_enum():
    edge = FrameworkEdgeFactory.create_edge("src_id", "dst_id", SemanticEdgeType.HANDLES)
    assert edge.source_id == "src_id"
    assert edge.target_id == "dst_id"
    assert edge.edge_type == SemanticEdgeType.HANDLES


def test_edge_factory_create_edge_with_string():
    edge = FrameworkEdgeFactory.create_edge("src_id", "dst_id", "DECLARES")
    assert edge.edge_type == SemanticEdgeType.DECLARES


def test_edge_factory_create_edge_with_attributes():
    edge = FrameworkEdgeFactory.create_edge("src_id", "dst_id", SemanticEdgeType.PROTECTS, attributes={"weight": 1.0})
    assert edge.attributes["weight"] == 1.0


def test_edge_factory_all_edge_types():
    for etype in SemanticEdgeType:
        edge = FrameworkEdgeFactory.create_edge("s", "t", etype)
        assert edge.edge_type == etype


# ============================================================================
# 3. Builder Context Tests (21-25)
# ============================================================================


def test_builder_options_defaults():
    opts = BuilderOptions()
    assert opts.auto_freeze is True
    assert opts.auto_optimize is True
    assert opts.generator_version == "1.0.0"


def test_builder_context_defaults():
    ctx = BuilderContext()
    assert len(ctx.isr.routes) == 0
    assert ctx.options.auto_freeze is True


def test_builder_context_custom():
    opts = BuilderOptions(auto_freeze=False)
    ctx = BuilderContext(options=opts)
    assert ctx.options.auto_freeze is False


def test_builder_context_with_isr(sample_isr):
    ctx = BuilderContext(isr=sample_isr)
    assert len(ctx.isr.routes) == 1


def test_builder_context_registry_and_symbol_table():
    ctx = BuilderContext()
    assert ctx.registry is not None
    assert ctx.symbol_table is not None


# ============================================================================
# 4. FrameworkGraphBuilder Tests (26-40)
# ============================================================================


def test_builder_build_from_isr(sample_isr):
    opts = BuilderOptions(auto_freeze=False)
    ctx = BuilderContext(isr=sample_isr, options=opts)
    builder = FrameworkGraphBuilder(context=ctx)

    graph = builder.build()
    assert len(graph.nodes()) == 8
    assert len(graph.edges()) > 0
    assert builder.is_frozen is False


def test_builder_auto_freeze():
    opts = BuilderOptions(auto_freeze=True)
    ctx = BuilderContext(options=opts)
    builder = FrameworkGraphBuilder(context=ctx)

    graph = builder.build()
    assert builder.is_frozen is True


def test_builder_freeze_method(sample_isr):
    opts = BuilderOptions(auto_freeze=False)
    builder = FrameworkGraphBuilder(context=BuilderContext(isr=sample_isr, options=opts))
    builder.build()

    assert builder.is_frozen is False
    graph = builder.freeze()
    assert builder.is_frozen is True


def test_builder_mutation_on_frozen_raises_error(sample_isr):
    builder = FrameworkGraphBuilder(context=BuilderContext(isr=sample_isr))
    builder.build()
    builder.freeze()

    dummy_node = FrameworkSemanticNode(id="x", node_type=SemanticNodeType.ROUTE, name="x")

    with pytest.raises(GraphFrozenError):
        builder.build()

    with pytest.raises(GraphFrozenError):
        builder.update(dummy_node)

    with pytest.raises(GraphFrozenError):
        builder.replace("x", dummy_node)

    with pytest.raises(GraphFrozenError):
        builder.remove("x")


def test_builder_clone(sample_isr):
    opts = BuilderOptions(auto_freeze=False)
    builder = FrameworkGraphBuilder(context=BuilderContext(isr=sample_isr, options=opts))
    builder.build()
    builder.freeze()

    cloned_builder = builder.clone()
    assert cloned_builder.is_frozen is False
    assert len(cloned_builder._graph.nodes()) == len(builder._graph.nodes())


def test_builder_rebuild(sample_isr):
    opts = BuilderOptions(auto_freeze=False)
    builder = FrameworkGraphBuilder(context=BuilderContext(isr=sample_isr, options=opts))
    builder.build()

    empty_isr = IntermediateSemanticRepresentation()
    new_graph = builder.rebuild(empty_isr)
    assert len(new_graph.nodes()) == 0


def test_builder_update_node():
    opts = BuilderOptions(auto_freeze=False)
    builder = FrameworkGraphBuilder(context=BuilderContext(options=opts))
    node = FrameworkSemanticNode(id="n1", node_type=SemanticNodeType.ROUTE, name="n1")

    graph = builder.update(node)
    assert len(graph.nodes()) == 1
    assert graph.nodes()[0].id == "n1"


def test_builder_replace_node():
    opts = BuilderOptions(auto_freeze=False)
    builder = FrameworkGraphBuilder(context=BuilderContext(options=opts))
    n1 = FrameworkSemanticNode(id="n1", node_type=SemanticNodeType.ROUTE, name="Original")
    n2 = FrameworkSemanticNode(id="n1", node_type=SemanticNodeType.ROUTE, name="Replaced")

    builder.update(n1)
    graph = builder.replace("n1", n2)
    assert len(graph.nodes()) == 1
    assert graph.nodes()[0].name == "Replaced"


def test_builder_remove_node():
    opts = BuilderOptions(auto_freeze=False)
    builder = FrameworkGraphBuilder(context=BuilderContext(options=opts))
    n1 = FrameworkSemanticNode(id="n1", node_type=SemanticNodeType.ROUTE, name="Node1")

    builder.update(n1)
    assert len(builder._graph.nodes()) == 1

    graph = builder.remove("n1")
    assert len(graph.nodes()) == 0


def test_builder_relationships_handles(sample_route, sample_handler):
    isr = IntermediateSemanticRepresentation(routes=(sample_route,), handlers=(sample_handler,))
    opts = BuilderOptions(auto_freeze=False)
    builder = FrameworkGraphBuilder(context=BuilderContext(isr=isr, options=opts))

    graph = builder.build()
    handles_edges = [e for e in graph.edges() if e.edge_type == SemanticEdgeType.HANDLES]
    assert len(handles_edges) == 1


def test_builder_relationships_declares(sample_controller, sample_handler):
    isr = IntermediateSemanticRepresentation(controllers=(sample_controller,), handlers=(sample_handler,))
    opts = BuilderOptions(auto_freeze=False)
    builder = FrameworkGraphBuilder(context=BuilderContext(isr=isr, options=opts))

    graph = builder.build()
    declares_edges = [e for e in graph.edges() if e.edge_type == SemanticEdgeType.DECLARES]
    assert len(declares_edges) == 1


def test_builder_relationships_protects_mw(sample_route, sample_middleware):
    isr = IntermediateSemanticRepresentation(routes=(sample_route,), middlewares=(sample_middleware,))
    opts = BuilderOptions(auto_freeze=False)
    builder = FrameworkGraphBuilder(context=BuilderContext(isr=isr, options=opts))

    graph = builder.build()
    protects_edges = [e for e in graph.edges() if e.edge_type == SemanticEdgeType.PROTECTS]
    assert len(protects_edges) == 1


def test_builder_relationships_protects_auth(sample_route, sample_auth):
    isr = IntermediateSemanticRepresentation(routes=(sample_route,), auths=(sample_auth,))
    opts = BuilderOptions(auto_freeze=False)
    builder = FrameworkGraphBuilder(context=BuilderContext(isr=isr, options=opts))

    graph = builder.build()
    protects_edges = [e for e in graph.edges() if e.edge_type == SemanticEdgeType.PROTECTS]
    assert len(protects_edges) == 1


def test_builder_does_not_depend_on_ast():
    # Verify FrameworkGraphBuilder takes only BuilderContext / ISR
    builder = FrameworkGraphBuilder()
    assert hasattr(builder, "build")


def test_builder_symbol_table_populating(sample_route, sample_handler):
    isr = IntermediateSemanticRepresentation(routes=(sample_route,), handlers=(sample_handler,))
    ctx = BuilderContext(isr=isr, options=BuilderOptions(auto_freeze=False))
    builder = FrameworkGraphBuilder(context=ctx)
    builder.build()

    bindings = ctx.symbol_table.list_bindings()
    assert len(bindings) == 1
    assert bindings[0].handler_name == "login_handler"


# ============================================================================
# 5. FrameworkGraphOptimizer Tests (41-52)
# ============================================================================


def test_optimizer_deduplicate_nodes():
    optimizer = FrameworkGraphOptimizer()
    n1 = FrameworkSemanticNode(id="dup", node_type=SemanticNodeType.ROUTE, name="r1")
    n2 = FrameworkSemanticNode(id="dup", node_type=SemanticNodeType.ROUTE, name="r2")
    graph = FrameworkSemanticGraph(nodes={"n1": n1, "n2": n2})

    # Dict keyed by ID already deduplicates, but test optimizer method
    opt_graph = optimizer.deduplicate_nodes(graph)
    assert len(opt_graph.nodes()) == 1


def test_optimizer_deduplicate_edges():
    optimizer = FrameworkGraphOptimizer()
    e1 = FrameworkSemanticEdge(source_id="s", target_id="t", edge_type=SemanticEdgeType.HANDLES)
    e2 = FrameworkSemanticEdge(source_id="s", target_id="t", edge_type=SemanticEdgeType.HANDLES)
    graph = FrameworkSemanticGraph(edges=(e1, e2))

    opt_graph = optimizer.deduplicate_edges(graph)
    assert len(opt_graph.edges()) == 1


def test_optimizer_normalize_labels():
    optimizer = FrameworkGraphOptimizer()
    n = FrameworkSemanticNode(id="n1", node_type=SemanticNodeType.ROUTE, name="n1", labels=("route", "get"))
    graph = FrameworkSemanticGraph(nodes={"n1": n})

    opt_graph = optimizer.normalize_labels(graph)
    assert opt_graph.nodes()[0].labels == ("GET", "ROUTE")


def test_optimizer_enforce_canonical_ordering():
    optimizer = FrameworkGraphOptimizer()
    n2 = FrameworkSemanticNode(id="b_node", node_type=SemanticNodeType.ROUTE, name="b")
    n1 = FrameworkSemanticNode(id="a_node", node_type=SemanticNodeType.ROUTE, name="a")
    graph = FrameworkSemanticGraph(nodes={"b_node": n2, "a_node": n1})

    opt_graph = optimizer.enforce_canonical_ordering(graph)
    node_ids = [n.id for n in opt_graph.nodes()]
    assert node_ids == ["a_node", "b_node"]


def test_optimizer_remove_orphan_nodes():
    optimizer = FrameworkGraphOptimizer()
    n_route = FrameworkSemanticNode(id="r", node_type=SemanticNodeType.ROUTE, name="r")
    n_config = FrameworkSemanticNode(id="cfg", node_type=SemanticNodeType.CONFIG, name="cfg")
    graph = FrameworkSemanticGraph(nodes={"r": n_route, "cfg": n_config})

    opt_graph = optimizer.remove_orphan_nodes(graph)
    # Config is an orphan without edges, Route is kept as root
    node_ids = [n.id for n in opt_graph.nodes()]
    assert "r" in node_ids
    assert "cfg" not in node_ids


def test_optimizer_full_optimize_pass(sample_isr):
    builder = FrameworkGraphBuilder(context=BuilderContext(isr=sample_isr, options=BuilderOptions(auto_freeze=False)))
    graph = builder.build()

    optimizer = FrameworkGraphOptimizer()
    opt_graph = optimizer.optimize(graph)
    assert len(opt_graph.nodes()) > 0


def test_optimizer_empty_graph():
    optimizer = FrameworkGraphOptimizer()
    graph = FrameworkSemanticGraph()
    opt_graph = optimizer.optimize(graph)
    assert len(opt_graph.nodes()) == 0


def test_optimizer_preserves_versions():
    optimizer = FrameworkGraphOptimizer()
    graph = FrameworkSemanticGraph(schema_version="2.0", generator_version="2.0.0")
    opt_graph = optimizer.optimize(graph)
    assert opt_graph.schema_version == "2.0"
    assert opt_graph.generator_version == "2.0.0"


def test_optimizer_deduplicate_edges_different_types():
    optimizer = FrameworkGraphOptimizer()
    e1 = FrameworkSemanticEdge(source_id="s", target_id="t", edge_type=SemanticEdgeType.HANDLES)
    e2 = FrameworkSemanticEdge(source_id="s", target_id="t", edge_type=SemanticEdgeType.PROTECTS)
    graph = FrameworkSemanticGraph(edges=(e1, e2))

    opt_graph = optimizer.deduplicate_edges(graph)
    assert len(opt_graph.edges()) == 2


def test_optimizer_remove_orphans_with_connected_nodes():
    optimizer = FrameworkGraphOptimizer()
    n1 = FrameworkSemanticNode(id="n1", node_type=SemanticNodeType.HANDLER, name="h1")
    n2 = FrameworkSemanticNode(id="n2", node_type=SemanticNodeType.HANDLER, name="h2")
    n3 = FrameworkSemanticNode(id="orphan", node_type=SemanticNodeType.HANDLER, name="orphan")
    e = FrameworkSemanticEdge(source_id="n1", target_id="n2", edge_type=SemanticEdgeType.CALLS)
    graph = FrameworkSemanticGraph(nodes={"n1": n1, "n2": n2, "orphan": n3}, edges=(e,))

    opt_graph = optimizer.remove_orphan_nodes(graph)
    node_ids = [n.id for n in opt_graph.nodes()]
    assert "n1" in node_ids
    assert "n2" in node_ids
    assert "orphan" not in node_ids


def test_optimizer_idempotence():
    optimizer = FrameworkGraphOptimizer()
    n = FrameworkSemanticNode(id="n1", node_type=SemanticNodeType.ROUTE, name="r1")
    graph = FrameworkSemanticGraph(nodes={"n1": n})

    opt1 = optimizer.optimize(graph)
    opt2 = optimizer.optimize(opt1)
    assert opt1.to_dict() == opt2.to_dict()


def test_optimizer_normalize_labels_duplicates():
    optimizer = FrameworkGraphOptimizer()
    n = FrameworkSemanticNode(id="n1", node_type=SemanticNodeType.ROUTE, name="r", labels=("route", "ROUTE", "Route"))
    graph = FrameworkSemanticGraph(nodes={"n1": n})

    opt_graph = optimizer.normalize_labels(graph)
    assert opt_graph.nodes()[0].labels == ("ROUTE",)


# ============================================================================
# 6. FrameworkGraphIntegrityChecker Tests (53-64)
# ============================================================================


def test_integrity_clean_graph(sample_isr):
    builder = FrameworkGraphBuilder(context=BuilderContext(isr=sample_isr, options=BuilderOptions(auto_freeze=False)))
    graph = builder.build()

    checker = FrameworkGraphIntegrityChecker()
    diags = checker.check(graph)
    errors = [d for d in diags if d.severity == "ERROR"]
    assert len(errors) == 0


def test_integrity_dangling_edge_source():
    checker = FrameworkGraphIntegrityChecker()
    n_target = FrameworkSemanticNode(id="t", node_type=SemanticNodeType.HANDLER, name="h")
    e = FrameworkSemanticEdge(source_id="non_existent", target_id="t", edge_type=SemanticEdgeType.HANDLES)
    graph = FrameworkSemanticGraph(nodes={"t": n_target}, edges=(e,))

    diags = checker.check(graph)
    assert any("Dangling edge source" in d.message for d in diags)


def test_integrity_dangling_edge_target():
    checker = FrameworkGraphIntegrityChecker()
    n_source = FrameworkSemanticNode(id="s", node_type=SemanticNodeType.ROUTE, name="r")
    e = FrameworkSemanticEdge(source_id="s", target_id="non_existent", edge_type=SemanticEdgeType.HANDLES)
    graph = FrameworkSemanticGraph(nodes={"s": n_source}, edges=(e,))

    diags = checker.check(graph)
    assert any("Dangling edge target" in d.message for d in diags)


def test_integrity_duplicate_edge_warning():
    checker = FrameworkGraphIntegrityChecker()
    n1 = FrameworkSemanticNode(id="s", node_type=SemanticNodeType.ROUTE, name="r")
    n2 = FrameworkSemanticNode(id="t", node_type=SemanticNodeType.HANDLER, name="h")
    e1 = FrameworkSemanticEdge(source_id="s", target_id="t", edge_type=SemanticEdgeType.HANDLES)
    e2 = FrameworkSemanticEdge(source_id="s", target_id="t", edge_type=SemanticEdgeType.HANDLES)
    graph = FrameworkSemanticGraph(nodes={"s": n1, "t": n2}, edges=(e1, e2))

    diags = checker.check(graph)
    assert any("Duplicate edge detected" in d.message for d in diags)


def test_integrity_cycle_detection():
    checker = FrameworkGraphIntegrityChecker()
    n1 = FrameworkSemanticNode(id="n1", node_type=SemanticNodeType.HANDLER, name="h1")
    n2 = FrameworkSemanticNode(id="n2", node_type=SemanticNodeType.HANDLER, name="h2")
    e1 = FrameworkSemanticEdge(source_id="n1", target_id="n2", edge_type=SemanticEdgeType.CALLS)
    e2 = FrameworkSemanticEdge(source_id="n2", target_id="n1", edge_type=SemanticEdgeType.CALLS)
    graph = FrameworkSemanticGraph(nodes={"n1": n1, "n2": n2}, edges=(e1, e2))

    diags = checker.check(graph)
    assert any("Cycle detected" in d.message for d in diags)


def test_integrity_disconnected_subcomponents_info():
    checker = FrameworkGraphIntegrityChecker()
    n1 = FrameworkSemanticNode(id="n1", node_type=SemanticNodeType.ROUTE, name="r1")
    n2 = FrameworkSemanticNode(id="n2", node_type=SemanticNodeType.ROUTE, name="r2")
    graph = FrameworkSemanticGraph(nodes={"n1": n1, "n2": n2})

    diags = checker.check(graph)
    assert any("disconnected subcomponents" in d.message for d in diags)


def test_integrity_empty_graph():
    checker = FrameworkGraphIntegrityChecker()
    graph = FrameworkSemanticGraph()
    diags = checker.check(graph)
    assert len(diags) == 0


def test_integrity_self_loop():
    checker = FrameworkGraphIntegrityChecker()
    n1 = FrameworkSemanticNode(id="n1", node_type=SemanticNodeType.HANDLER, name="h1")
    e1 = FrameworkSemanticEdge(source_id="n1", target_id="n1", edge_type=SemanticEdgeType.CALLS)
    graph = FrameworkSemanticGraph(nodes={"n1": n1}, edges=(e1,))

    diags = checker.check(graph)
    assert any("Cycle detected" in d.message for d in diags)


def test_integrity_dag_no_cycles():
    checker = FrameworkGraphIntegrityChecker()
    n1 = FrameworkSemanticNode(id="n1", node_type=SemanticNodeType.ROUTE, name="r")
    n2 = FrameworkSemanticNode(id="n2", node_type=SemanticNodeType.HANDLER, name="h")
    n3 = FrameworkSemanticNode(id="n3", node_type=SemanticNodeType.MODEL, name="m")
    e1 = FrameworkSemanticEdge(source_id="n1", target_id="n2", edge_type=SemanticEdgeType.HANDLES)
    e2 = FrameworkSemanticEdge(source_id="n2", target_id="n3", edge_type=SemanticEdgeType.USES)
    graph = FrameworkSemanticGraph(nodes={"n1": n1, "n2": n2, "n3": n3}, edges=(e1, e2))

    diags = checker.check(graph)
    assert not any("Cycle detected" in d.message for d in diags)


def test_integrity_returns_semantic_diagnostic_objects():
    checker = FrameworkGraphIntegrityChecker()
    n1 = FrameworkSemanticNode(id="s", node_type=SemanticNodeType.ROUTE, name="r")
    e1 = FrameworkSemanticEdge(source_id="s", target_id="bad", edge_type=SemanticEdgeType.HANDLES)
    graph = FrameworkSemanticGraph(nodes={"s": n1}, edges=(e1,))

    diags = checker.check(graph)
    assert isinstance(diags[0], SemanticDiagnostic)


def test_integrity_checker_multiple_dangling_edges():
    checker = FrameworkGraphIntegrityChecker()
    e1 = FrameworkSemanticEdge(source_id="x", target_id="y", edge_type=SemanticEdgeType.HANDLES)
    graph = FrameworkSemanticGraph(edges=(e1,))

    diags = checker.check(graph)
    # Both x and y are missing
    assert len([d for d in diags if "Dangling edge" in d.message]) == 2


def test_integrity_valid_single_component():
    checker = FrameworkGraphIntegrityChecker()
    n1 = FrameworkSemanticNode(id="n1", node_type=SemanticNodeType.ROUTE, name="r")
    n2 = FrameworkSemanticNode(id="n2", node_type=SemanticNodeType.HANDLER, name="h")
    e = FrameworkSemanticEdge(source_id="n1", target_id="n2", edge_type=SemanticEdgeType.HANDLES)
    graph = FrameworkSemanticGraph(nodes={"n1": n1, "n2": n2}, edges=(e,))

    diags = checker.check(graph)
    assert not any("disconnected subcomponents" in d.message for d in diags)


# ============================================================================
# 7. FrameworkGraphSerializer Tests (65-73)
# ============================================================================


def test_serializer_json_roundtrip(sample_isr):
    builder = FrameworkGraphBuilder(context=BuilderContext(isr=sample_isr, options=BuilderOptions(auto_freeze=False)))
    graph = builder.build()

    json_str = FrameworkGraphSerializer.to_json(graph)
    graph2 = FrameworkGraphSerializer.from_json(json_str)

    assert len(graph2.nodes()) == len(graph.nodes())
    assert len(graph2.edges()) == len(graph.edges())


def test_serializer_compressed_json_roundtrip(sample_isr):
    builder = FrameworkGraphBuilder(context=BuilderContext(isr=sample_isr, options=BuilderOptions(auto_freeze=False)))
    graph = builder.build()

    compressed_bytes = FrameworkGraphSerializer.to_compressed_json(graph)
    assert isinstance(compressed_bytes, bytes)

    graph2 = FrameworkGraphSerializer.from_compressed_json(compressed_bytes)
    assert len(graph2.nodes()) == len(graph.nodes())


def test_serializer_msgpack_roundtrip(sample_isr):
    builder = FrameworkGraphBuilder(context=BuilderContext(isr=sample_isr, options=BuilderOptions(auto_freeze=False)))
    graph = builder.build()

    msgpack_bytes = FrameworkGraphSerializer.to_msgpack(graph)
    assert isinstance(msgpack_bytes, bytes)

    graph2 = FrameworkGraphSerializer.from_msgpack(msgpack_bytes)
    assert len(graph2.nodes()) == len(graph.nodes())


def test_serializer_binary_snapshot_roundtrip(sample_isr):
    builder = FrameworkGraphBuilder(context=BuilderContext(isr=sample_isr, options=BuilderOptions(auto_freeze=False)))
    graph = builder.build()

    binary_bytes = FrameworkGraphSerializer.to_binary(graph)
    assert binary_bytes.startswith(b"KSG1")

    graph2 = FrameworkGraphSerializer.from_binary(binary_bytes)
    assert len(graph2.nodes()) == len(graph.nodes())


def test_serializer_invalid_json_raises():
    with pytest.raises(SerializationError):
        FrameworkGraphSerializer.from_json("invalid json {")


def test_serializer_invalid_compressed_json_raises():
    with pytest.raises(SerializationError):
        FrameworkGraphSerializer.from_compressed_json(b"not compressed data")


def test_serializer_invalid_binary_header_raises():
    with pytest.raises(SerializationError):
        FrameworkGraphSerializer.from_binary(b"BADHEADER12345")


def test_serializer_short_binary_raises():
    with pytest.raises(SerializationError):
        FrameworkGraphSerializer.from_binary(b"KSG1")


def test_serializer_dict_roundtrip(sample_isr):
    builder = FrameworkGraphBuilder(context=BuilderContext(isr=sample_isr, options=BuilderOptions(auto_freeze=False)))
    graph = builder.build()

    d = FrameworkGraphSerializer.to_dict(graph)
    graph2 = FrameworkGraphSerializer.from_dict(d)
    assert len(graph2.nodes()) == len(graph.nodes())


# ============================================================================
# 8. GraphStatistics Tests (74-78)
# ============================================================================


def test_graph_statistics_compute(sample_isr):
    builder = FrameworkGraphBuilder(context=BuilderContext(isr=sample_isr, options=BuilderOptions(auto_freeze=False)))
    graph = builder.build()

    stats = GraphStatistics.compute(graph)
    assert stats.node_count == 8
    assert stats.route_count == 1
    assert stats.controller_count == 1
    assert stats.middleware_count == 1
    assert stats.handler_count == 1
    assert stats.model_count == 1
    assert stats.connected_components >= 1


def test_graph_statistics_empty_graph():
    graph = FrameworkSemanticGraph()
    stats = GraphStatistics.compute(graph)
    assert stats.node_count == 0
    assert stats.edge_count == 0
    assert stats.density == 0.0
    assert stats.depth == 0


def test_graph_statistics_density_calculation():
    n1 = FrameworkSemanticNode(id="n1", node_type=SemanticNodeType.ROUTE, name="r")
    n2 = FrameworkSemanticNode(id="n2", node_type=SemanticNodeType.HANDLER, name="h")
    e1 = FrameworkSemanticEdge(source_id="n1", target_id="n2", edge_type=SemanticEdgeType.HANDLES)
    graph = FrameworkSemanticGraph(nodes={"n1": n1, "n2": n2}, edges=(e1,))

    stats = GraphStatistics.compute(graph)
    # Density for 2 nodes, 1 edge = 1 / (2 * 1) = 0.5
    assert stats.density == 0.5


def test_graph_statistics_depth_calculation():
    n1 = FrameworkSemanticNode(id="n1", node_type=SemanticNodeType.ROUTE, name="r")
    n2 = FrameworkSemanticNode(id="n2", node_type=SemanticNodeType.HANDLER, name="h")
    n3 = FrameworkSemanticNode(id="n3", node_type=SemanticNodeType.MODEL, name="m")
    e1 = FrameworkSemanticEdge(source_id="n1", target_id="n2", edge_type=SemanticEdgeType.HANDLES)
    e2 = FrameworkSemanticEdge(source_id="n2", target_id="n3", edge_type=SemanticEdgeType.USES)
    graph = FrameworkSemanticGraph(nodes={"n1": n1, "n2": n2, "n3": n3}, edges=(e1, e2))

    stats = GraphStatistics.compute(graph)
    assert stats.depth == 2


def test_graph_statistics_to_dict():
    stats = GraphStatistics(
        node_count=10,
        edge_count=5,
        route_count=2,
        controller_count=1,
        middleware_count=1,
        handler_count=2,
        model_count=2,
        density=0.1,
        depth=3,
        connected_components=2,
    )
    d = stats.to_dict()
    assert d["node_count"] == 10
    assert d["depth"] == 3


# ============================================================================
# 9. FrameworkGraphSnapshot Tests (79-83)
# ============================================================================


def test_snapshot_fingerprint_determinism(sample_isr):
    builder = FrameworkGraphBuilder(context=BuilderContext(isr=sample_isr, options=BuilderOptions(auto_freeze=False)))
    graph = builder.build()

    snapshot = FrameworkGraphSnapshot()
    fp1 = snapshot.fingerprint(graph)
    fp2 = snapshot.fingerprint(graph)
    assert fp1 == fp2


def test_snapshot_hash_sha256(sample_isr):
    builder = FrameworkGraphBuilder(context=BuilderContext(isr=sample_isr, options=BuilderOptions(auto_freeze=False)))
    graph = builder.build()

    snapshot = FrameworkGraphSnapshot()
    h1 = snapshot.hash(graph)
    h2 = snapshot.hash(graph)
    assert h1 == h2
    assert len(h1) == 64


def test_snapshot_compare_identical(sample_isr):
    builder = FrameworkGraphBuilder(context=BuilderContext(isr=sample_isr, options=BuilderOptions(auto_freeze=False)))
    graph = builder.build()

    snapshot = FrameworkGraphSnapshot()
    diff = snapshot.compare(graph, graph)
    assert diff.is_identical is True
    assert len(diff.added_nodes) == 0


def test_snapshot_compare_diff_nodes(sample_isr):
    builder1 = FrameworkGraphBuilder(context=BuilderContext(isr=sample_isr, options=BuilderOptions(auto_freeze=False)))
    graph1 = builder1.build()

    # Modify ISR for graph2
    r_extra = RouteDefinition(path="/extra", method="GET", handler="h_extra")
    isr2 = IntermediateSemanticRepresentation(routes=(r_extra,))
    builder2 = FrameworkGraphBuilder(context=BuilderContext(isr=isr2, options=BuilderOptions(auto_freeze=False)))
    graph2 = builder2.build()

    snapshot = FrameworkGraphSnapshot()
    diff = snapshot.compare(graph1, graph2)
    assert diff.is_identical is False
    assert len(diff.added_nodes) > 0 or len(diff.removed_nodes) > 0


def test_snapshot_diff_to_dict():
    snapshot = FrameworkGraphSnapshot()
    graph1 = FrameworkSemanticGraph()
    graph2 = FrameworkSemanticGraph()
    diff = snapshot.compare(graph1, graph2)
    d = diff.to_dict()
    assert d["is_identical"] is True
