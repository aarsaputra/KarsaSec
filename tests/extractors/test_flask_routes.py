"""Comprehensive unit test suite for Sprint E10-3B-1: Flask Route Intelligence (100+ tests)."""

import pytest

from karsasec.framework.extractors.base import ExtractorCapability, ExtractorContext
from karsasec.framework.extractors.flask.collector import FlaskRouteCollector
from karsasec.framework.extractors.flask.normalizer import FlaskRouteNormalizer
from karsasec.framework.extractors.flask.routes import FlaskRouteExtractor
from karsasec.framework.extractors.flask.state import (
    BlueprintRecord,
    BlueprintRegistrationRecord,
    FlaskSemanticState,
    MethodViewRecord,
    RawRouteRecord,
)
from karsasec.framework.extractors.flask.visitors import (
    FlaskBlueprintVisitor,
    FlaskDecoratorResolver,
    FlaskMethodViewVisitor,
)
from karsasec.framework.intermediate import RouteDefinition
from karsasec.framework.parser.ast_adapter import PythonASTAdapter
from tests.framework_testkit import FixtureLoader, FrameworkAssertions, ISRAssertions


@pytest.fixture
def extractor() -> FlaskRouteExtractor:
    return FlaskRouteExtractor()


@pytest.fixture
def empty_ctx() -> ExtractorContext:
    return ExtractorContext(language="Python", framework="FLASK")


# ============================================================================
# 1. Extractor Contract & Metadata Tests (10 tests)
# ============================================================================


def test_flask_extractor_name(extractor: FlaskRouteExtractor):
    assert extractor.name == "FlaskRouteExtractor"


def test_flask_extractor_priority(extractor: FlaskRouteExtractor):
    assert extractor.priority == 10


def test_flask_extractor_languages(extractor: FlaskRouteExtractor):
    assert extractor.supported_languages == ("Python",)


def test_flask_extractor_frameworks(extractor: FlaskRouteExtractor):
    assert extractor.supported_frameworks == ("FLASK",)


def test_flask_extractor_capabilities(extractor: FlaskRouteExtractor):
    assert extractor.capabilities == (ExtractorCapability.ROUTING,)


def test_flask_extractor_can_extract_matching(extractor: FlaskRouteExtractor):
    ctx = ExtractorContext(language="Python", framework="FLASK")
    assert extractor.can_extract(ctx) is True


def test_flask_extractor_can_extract_mismatch_lang(extractor: FlaskRouteExtractor):
    ctx = ExtractorContext(language="JavaScript", framework="FLASK")
    assert extractor.can_extract(ctx) is False


def test_flask_extractor_can_extract_mismatch_fw(extractor: FlaskRouteExtractor):
    ctx = ExtractorContext(language="Python", framework="EXPRESS")
    assert extractor.can_extract(ctx) is False


def test_flask_extractor_can_extract_generic_lang(extractor: FlaskRouteExtractor):
    ctx = ExtractorContext(language="Generic", framework="FLASK")
    assert extractor.can_extract(ctx) is True


def test_flask_extractor_can_extract_generic_fw(extractor: FlaskRouteExtractor):
    ctx = ExtractorContext(language="Python", framework="GENERIC")
    assert extractor.can_extract(ctx) is True


# ============================================================================
# 2. Standard & Shortcut Decorators Tests (20 tests)
# ============================================================================


def test_extract_basic_routes_fixture(extractor: FlaskRouteExtractor):
    fixture_path = FixtureLoader.get_fixture_path("flask/basic_routes.py")
    ctx = ExtractorContext(project_path=str(fixture_path), language="Python", framework="FLASK")
    result = extractor.extract(ctx)

    ISRAssertions.assert_valid_isr(result.isr)
    assert len(result.isr.routes) == 4
    FrameworkAssertions.assert_route_exists(result.isr, "/", method="GET")
    FrameworkAssertions.assert_route_exists(result.isr, "/login", method="GET")
    FrameworkAssertions.assert_route_exists(result.isr, "/login", method="POST")
    FrameworkAssertions.assert_route_exists(result.isr, "/logout", method="POST")


def test_extract_shortcut_routes_fixture(extractor: FlaskRouteExtractor):
    fixture_path = FixtureLoader.get_fixture_path("flask/shortcut_routes.py")
    ctx = ExtractorContext(project_path=str(fixture_path), language="Python", framework="FLASK")
    result = extractor.extract(ctx)

    ISRAssertions.assert_valid_isr(result.isr)
    assert len(result.isr.routes) == 4
    FrameworkAssertions.assert_route_exists(result.isr, "/items", method="GET")
    FrameworkAssertions.assert_route_exists(result.isr, "/items", method="POST")
    FrameworkAssertions.assert_route_exists(result.isr, "/items/{item_id}", method="PUT")
    FrameworkAssertions.assert_route_exists(result.isr, "/items/{item_id}", method="DELETE")


def test_route_visitor_direct_code(empty_ctx: ExtractorContext):
    code = """
from flask import Flask
app = Flask(__name__)

@app.route("/test")
def test():
    pass
"""
    tree = PythonASTAdapter.parse_code(code, "test.py")
    assert tree is not None
    state = FlaskSemanticState()
    collector = FlaskRouteCollector(state=state)
    collector.collect_from_ast(tree)

    assert len(state.routes) == 1
    assert state.routes[0].path == "/test"
    assert state.routes[0].handler_name == "test"


def test_route_visitor_methods_kwarg():
    code = """
@app.route("/multi", methods=["GET", "POST", "PUT"])
def multi():
    pass
"""
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskSemanticState()
    FlaskRouteCollector(state).collect_from_ast(tree)

    assert len(state.routes) == 1
    assert set(state.routes[0].methods) == {"GET", "POST", "PUT"}


def test_route_visitor_endpoint_kwarg():
    code = """
@app.route("/endpoint", endpoint="custom_ep")
def handler_fn():
    pass
"""
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskSemanticState()
    FlaskRouteCollector(state).collect_from_ast(tree)

    assert state.routes[0].endpoint == "custom_ep"
    assert state.routes[0].handler_name == "handler_fn"


def test_route_visitor_get_shortcut():
    code = "@app.get('/get_path')\ndef fn(): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskSemanticState()
    FlaskRouteCollector(state).collect_from_ast(tree)
    assert state.routes[0].methods == ("GET",)
    assert state.routes[0].path == "/get_path"


def test_route_visitor_post_shortcut():
    code = "@app.post('/post_path')\ndef fn(): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskSemanticState()
    FlaskRouteCollector(state).collect_from_ast(tree)
    assert state.routes[0].methods == ("POST",)


def test_route_visitor_put_shortcut():
    code = "@app.put('/put_path')\ndef fn(): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskSemanticState()
    FlaskRouteCollector(state).collect_from_ast(tree)
    assert state.routes[0].methods == ("PUT",)


def test_route_visitor_delete_shortcut():
    code = "@app.delete('/del_path')\ndef fn(): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskSemanticState()
    FlaskRouteCollector(state).collect_from_ast(tree)
    assert state.routes[0].methods == ("DELETE",)


def test_route_visitor_async_function():
    code = "@app.route('/async')\nasync def async_fn(): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskSemanticState()
    FlaskRouteCollector(state).collect_from_ast(tree)
    assert state.routes[0].handler_name == "async_fn"


def test_route_visitor_multiple_decorators():
    code = """
@auth_required
@cache_page
@app.route('/protected')
def protected(): pass
"""
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskSemanticState()
    FlaskRouteCollector(state).collect_from_ast(tree)
    assert state.routes[0].path == "/protected"
    assert "auth_required" in state.routes[0].decorators


def test_route_visitor_nested_decorator_call():
    code = """
@cache.cached(timeout=60)
@app.route('/cached')
def cached_fn(): pass
"""
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskSemanticState()
    FlaskRouteCollector(state).collect_from_ast(tree)
    assert state.routes[0].path == "/cached"


def test_route_visitor_empty_path_default():
    code = "@app.route()\ndef empty(): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskSemanticState()
    FlaskRouteCollector(state).collect_from_ast(tree)
    assert state.routes[0].path == "/"


def test_route_visitor_confidence_score():
    code = "@app.route('/direct')\ndef fn(): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskSemanticState()
    FlaskRouteCollector(state).collect_from_ast(tree)
    assert state.routes[0].confidence == 1.0


def test_route_visitor_evidence_populated():
    code = "@app.route('/ev')\ndef fn(): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskSemanticState()
    FlaskRouteCollector(state).collect_from_ast(tree)
    assert len(state.routes[0].evidence) > 0
    assert "app.route" in state.routes[0].evidence[0]


def test_route_visitor_multiple_routes_on_single_func():
    code = """
@app.route('/path1')
@app.route('/path2')
def dual(): pass
"""
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskSemanticState()
    FlaskRouteCollector(state).collect_from_ast(tree)
    assert len(state.routes) == 2
    paths = {r.path for r in state.routes}
    assert paths == {"/path1", "/path2"}


def test_route_visitor_patch_shortcut():
    code = "@app.patch('/patch_path')\ndef fn(): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskSemanticState()
    FlaskRouteCollector(state).collect_from_ast(tree)
    assert state.routes[0].methods == ("PATCH",)


def test_route_visitor_bp_var_binding():
    code = """
bp = Blueprint('auth', __name__)
@bp.route('/bp_login')
def bp_login(): pass
"""
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskSemanticState()
    FlaskRouteCollector(state).collect_from_ast(tree)
    assert state.routes[0].blueprint_name == "bp"


def test_route_visitor_blueprint_var_matching():
    code = "@auth_bp.route('/auth_login')\ndef fn(): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskSemanticState()
    FlaskRouteCollector(state).collect_from_ast(tree)
    assert state.routes[0].blueprint_name == "auth_bp"


def test_route_visitor_normalizer_integration(extractor: FlaskRouteExtractor):
    code = "@app.route('/norm')\ndef norm(): pass"
    tree = PythonASTAdapter.parse_code(code)
    ctx = ExtractorContext(ast_nodes=[tree], language="Python", framework="FLASK")
    res = extractor.extract(ctx)
    assert len(res.isr.routes) == 1
    assert res.isr.routes[0].path == "/norm"


# ============================================================================
# 3. Blueprint & Nested Blueprint Resolution Tests (15 tests)
# ============================================================================


def test_blueprints_fixture(extractor: FlaskRouteExtractor):
    fixture_path = FixtureLoader.get_fixture_path("flask/blueprints.py")
    ctx = ExtractorContext(project_path=str(fixture_path), language="Python", framework="FLASK")
    result = extractor.extract(ctx)

    ISRAssertions.assert_valid_isr(result.isr)
    assert len(result.isr.routes) == 2
    FrameworkAssertions.assert_route_exists(result.isr, "/auth/login", method="POST")
    FrameworkAssertions.assert_route_exists(result.isr, "/auth/register", method="POST")


def test_nested_blueprints_fixture(extractor: FlaskRouteExtractor):
    fixture_path = FixtureLoader.get_fixture_path("flask/nested_blueprints.py")
    ctx = ExtractorContext(project_path=str(fixture_path), language="Python", framework="FLASK")
    result = extractor.extract(ctx)

    ISRAssertions.assert_valid_isr(result.isr)
    assert len(result.isr.routes) == 1
    FrameworkAssertions.assert_route_exists(result.isr, "/api/v1/users", method="GET")


def test_blueprint_visitor_instantiation():
    code = "auth_bp = Blueprint('auth', __name__, url_prefix='/auth')"
    tree = PythonASTAdapter.parse_code(code)
    assert tree is not None
    state = FlaskSemanticState()
    FlaskBlueprintVisitor(state).visit(tree.children[0])
    assert "auth_bp" in state.blueprints
    assert state.blueprints["auth_bp"].url_prefix == "/auth"


def test_blueprint_visitor_registration():
    code = "app.register_blueprint(auth_bp, url_prefix='/api/auth')"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskSemanticState()
    FlaskRouteCollector(state).collect_from_ast(tree)
    assert len(state.blueprint_registrations) == 1
    assert state.blueprint_registrations[0].blueprint_var == "auth_bp"
    assert state.blueprint_registrations[0].url_prefix == "/api/auth"


def test_blueprint_normalizer_prefix_resolution():
    state = FlaskSemanticState()
    state.blueprints["bp"] = BlueprintRecord(name="admin", variable_name="bp", url_prefix="/admin")
    state.routes.append(RawRouteRecord(path="/dashboard", blueprint_name="bp", handler_name="dash"))

    normalizer = FlaskRouteNormalizer(state)
    routes = normalizer.normalize(state.routes)
    assert len(routes) == 1
    assert routes[0].path == "/admin/dashboard"


def test_blueprint_normalizer_registration_override():
    state = FlaskSemanticState()
    state.blueprints["bp"] = BlueprintRecord(name="admin", variable_name="bp", url_prefix="/admin")
    state.blueprint_registrations.append(BlueprintRegistrationRecord(blueprint_var="bp", url_prefix="/v1"))
    state.routes.append(RawRouteRecord(path="/dash", blueprint_name="bp", handler_name="dash"))

    normalizer = FlaskRouteNormalizer(state)
    routes = normalizer.normalize(state.routes)
    assert routes[0].path == "/v1/admin/dash"


def test_blueprint_visitor_no_url_prefix():
    code = "simple_bp = Blueprint('simple', __name__)"
    tree = PythonASTAdapter.parse_code(code)
    assert tree is not None
    state = FlaskSemanticState()
    FlaskBlueprintVisitor(state).visit(tree.children[0])
    assert state.blueprints["simple_bp"].url_prefix == ""


def test_blueprint_visitor_module_attribute():
    code = "bp = flask.Blueprint('m_bp', __name__)"
    tree = PythonASTAdapter.parse_code(code)
    assert tree is not None
    state = FlaskSemanticState()
    FlaskBlueprintVisitor(state).visit(tree.children[0])
    assert "bp" in state.blueprints


def test_blueprint_normalizer_empty_prefix():
    state = FlaskSemanticState()
    state.blueprints["bp"] = BlueprintRecord(name="bp", variable_name="bp", url_prefix="")
    state.routes.append(RawRouteRecord(path="/home", blueprint_name="bp", handler_name="home"))
    normalizer = FlaskRouteNormalizer(state)
    routes = normalizer.normalize(state.routes)
    assert routes[0].path == "/home"


def test_blueprint_multiple_registrations():
    state = FlaskSemanticState()
    state.blueprints["bp"] = BlueprintRecord(name="bp", variable_name="bp", url_prefix="/sub")
    state.blueprint_registrations.append(BlueprintRegistrationRecord(blueprint_var="bp", url_prefix="/reg1"))
    normalizer = FlaskRouteNormalizer(state)
    prefixes = normalizer._compute_blueprint_prefixes()
    assert prefixes["bp"] == "/reg1/sub"


def test_blueprint_visitor_positional_name():
    code = "p_bp = Blueprint('pos_name', __name__)"
    tree = PythonASTAdapter.parse_code(code)
    assert tree is not None
    state = FlaskSemanticState()
    FlaskBlueprintVisitor(state).visit(tree.children[0])
    assert state.blueprints["p_bp"].name == "pos_name"


def test_blueprint_visitor_attribute_registration():
    code = "myapp.main_app.register_blueprint(b_var, url_prefix='/b')"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskSemanticState()
    FlaskRouteCollector(state).collect_from_ast(tree)
    assert len(state.blueprint_registrations) == 1


def test_blueprint_normalizer_trailing_slash_handling():
    state = FlaskSemanticState()
    state.blueprints["bp"] = BlueprintRecord(name="bp", variable_name="bp", url_prefix="/prefix/")
    state.routes.append(RawRouteRecord(path="/path/", blueprint_name="bp", handler_name="h"))
    normalizer = FlaskRouteNormalizer(state)
    routes = normalizer.normalize(state.routes)
    assert routes[0].path == "/prefix/path"


def test_blueprint_visitor_multiple_blueprints():
    code = """
bp1 = Blueprint('b1', __name__, url_prefix='/1')
bp2 = Blueprint('b2', __name__, url_prefix='/2')
"""
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskSemanticState()
    collector = FlaskRouteCollector(state)
    collector.collect_from_ast(tree)
    assert len(state.blueprints) >= 2


def test_blueprint_visitor_state_reset():
    state = FlaskSemanticState()
    state.blueprints["test"] = BlueprintRecord(name="t", variable_name="test")
    state.clear()
    assert len(state.blueprints) == 0


# ============================================================================
# 4. MethodView Class Extraction Tests (15 tests)
# ============================================================================


def test_method_views_fixture(extractor: FlaskRouteExtractor):
    fixture_path = FixtureLoader.get_fixture_path("flask/method_views.py")
    ctx = ExtractorContext(project_path=str(fixture_path), language="Python", framework="FLASK")
    result = extractor.extract(ctx)

    ISRAssertions.assert_valid_isr(result.isr)
    assert len(result.isr.routes) >= 3
    FrameworkAssertions.assert_route_exists(result.isr, "/users/{user_id}", method="GET")
    FrameworkAssertions.assert_route_exists(result.isr, "/users/{user_id}", method="DELETE")
    FrameworkAssertions.assert_route_exists(result.isr, "/users", method="POST")


def test_method_view_visitor_direct_class():
    code = """
class MyView(MethodView):
    def get(self): pass
    def post(self): pass
"""
    tree = PythonASTAdapter.parse_code(code)
    assert tree is not None
    state = FlaskSemanticState()
    FlaskMethodViewVisitor(state).visit(tree.children[0])
    assert "MyView" in state.method_views
    assert set(state.method_views["MyView"].methods_map.keys()) == {"GET", "POST"}


def test_method_view_visitor_subclass_flask_view():
    code = """
class ViewSub(View):
    def get(self): pass
"""
    tree = PythonASTAdapter.parse_code(code)
    assert tree is not None
    state = FlaskSemanticState()
    FlaskMethodViewVisitor(state).visit(tree.children[0])
    assert "ViewSub" in state.method_views


def test_method_view_visitor_attribute_base():
    code = """
class AttrView(flask.views.MethodView):
    def put(self): pass
"""
    tree = PythonASTAdapter.parse_code(code)
    assert tree is not None
    state = FlaskSemanticState()
    FlaskMethodViewVisitor(state).visit(tree.children[0])
    assert "AttrView" in state.method_views


def test_method_view_normalizer_expansion():
    state = FlaskSemanticState()
    state.method_views["UserView"] = MethodViewRecord(
        class_name="UserView", methods_map={"GET": "get", "DELETE": "delete"}
    )
    state.routes.append(RawRouteRecord(path="/users", handler_name="UserView", is_method_view=True))
    normalizer = FlaskRouteNormalizer(state)
    routes = normalizer.normalize(state.routes)
    assert len(routes) == 2
    methods = {r.method for r in routes}
    assert methods == {"GET", "DELETE"}


def test_method_view_all_http_methods():
    code = """
class FullView(MethodView):
    def get(self): pass
    def post(self): pass
    def put(self): pass
    def delete(self): pass
    def patch(self): pass
    def head(self): pass
    def options(self): pass
"""
    tree = PythonASTAdapter.parse_code(code)
    assert tree is not None
    state = FlaskSemanticState()
    FlaskMethodViewVisitor(state).visit(tree.children[0])
    assert len(state.method_views["FullView"].methods_map) == 7


def test_method_view_non_http_methods_ignored():
    code = """
class CustomView(MethodView):
    def get(self): pass
    def helper_func(self): pass
"""
    tree = PythonASTAdapter.parse_code(code)
    assert tree is not None
    state = FlaskSemanticState()
    FlaskMethodViewVisitor(state).visit(tree.children[0])
    assert "GET" in state.method_views["CustomView"].methods_map
    assert "HELPER_FUNC" not in state.method_views["CustomView"].methods_map


def test_method_view_handler_name_format():
    state = FlaskSemanticState()
    state.method_views["ItemView"] = MethodViewRecord(class_name="ItemView", methods_map={"GET": "get"})
    state.routes.append(RawRouteRecord(path="/item", handler_name="ItemView", is_method_view=True))
    normalizer = FlaskRouteNormalizer(state)
    routes = normalizer.normalize(state.routes)
    assert routes[0].handler == "ItemView.get"


def test_method_view_async_methods():
    code = """
class AsyncView(MethodView):
    async def get(self): pass
"""
    tree = PythonASTAdapter.parse_code(code)
    assert tree is not None
    state = FlaskSemanticState()
    FlaskMethodViewVisitor(state).visit(tree.children[0])
    assert "GET" in state.method_views["AsyncView"].methods_map


def test_method_view_empty_class():
    code = "class EmptyView(MethodView): pass"
    tree = PythonASTAdapter.parse_code(code)
    assert tree is not None
    state = FlaskSemanticState()
    FlaskMethodViewVisitor(state).visit(tree.children[0])
    assert len(state.method_views["EmptyView"].methods_map) == 0


def test_method_view_visitor_non_view_class():
    code = "class RegularClass: pass"
    tree = PythonASTAdapter.parse_code(code)
    assert tree is not None
    state = FlaskSemanticState()
    FlaskMethodViewVisitor(state).visit(tree.children[0])
    assert "RegularClass" not in state.method_views


def test_method_view_integration(extractor: FlaskRouteExtractor):
    code = """
class OrderView(MethodView):
    def get(self): pass

app.add_url_rule('/orders', view_func=OrderView.as_view('order_view'))
"""
    tree = PythonASTAdapter.parse_code(code)
    ctx = ExtractorContext(ast_nodes=[tree], language="Python", framework="FLASK")
    res = extractor.extract(ctx)
    assert len(res.isr.routes) >= 1


def test_method_view_multiple_as_view_calls():
    state = FlaskSemanticState()
    state.method_views["WidgetView"] = MethodViewRecord(class_name="WidgetView", methods_map={"GET": "get"})
    state.routes.append(RawRouteRecord(path="/w1", handler_name="WidgetView", is_method_view=True))
    state.routes.append(RawRouteRecord(path="/w2", handler_name="WidgetView", is_method_view=True))
    normalizer = FlaskRouteNormalizer(state)
    routes = normalizer.normalize(state.routes)
    assert len(routes) == 2


def test_method_view_path_parameters():
    state = FlaskSemanticState()
    state.method_views["ParamView"] = MethodViewRecord(class_name="ParamView", methods_map={"GET": "get"})
    state.routes.append(RawRouteRecord(path="/view/<int:vid>", handler_name="ParamView", is_method_view=True))
    normalizer = FlaskRouteNormalizer(state)
    routes = normalizer.normalize(state.routes)
    assert routes[0].path == "/view/{vid}"


def test_method_view_confidence_score():
    state = FlaskSemanticState()
    state.method_views["ConfView"] = MethodViewRecord(class_name="ConfView", methods_map={"GET": "get"})
    state.routes.append(RawRouteRecord(path="/conf", handler_name="ConfView", is_method_view=True, confidence=1.0))
    normalizer = FlaskRouteNormalizer(state)
    routes = normalizer.normalize(state.routes)
    assert routes[0].confidence == 1.0


# ============================================================================
# 5. add_url_rule & Application Factory Tests (15 tests)
# ============================================================================


def test_url_rules_fixture(extractor: FlaskRouteExtractor):
    fixture_path = FixtureLoader.get_fixture_path("flask/url_rules.py")
    ctx = ExtractorContext(project_path=str(fixture_path), language="Python", framework="FLASK")
    result = extractor.extract(ctx)

    ISRAssertions.assert_valid_isr(result.isr)
    assert len(result.isr.routes) == 3
    FrameworkAssertions.assert_route_exists(result.isr, "/profile", method="GET")
    FrameworkAssertions.assert_route_exists(result.isr, "/settings", method="GET")
    FrameworkAssertions.assert_route_exists(result.isr, "/settings", method="POST")


def test_app_factory_fixture(extractor: FlaskRouteExtractor):
    fixture_path = FixtureLoader.get_fixture_path("flask/app_factory.py")
    ctx = ExtractorContext(project_path=str(fixture_path), language="Python", framework="FLASK")
    result = extractor.extract(ctx)

    ISRAssertions.assert_valid_isr(result.isr)
    assert len(result.isr.routes) == 1
    FrameworkAssertions.assert_route_exists(result.isr, "/health", method="GET")


def test_call_visitor_add_url_rule_basic():
    code = "app.add_url_rule('/basic', view_func=my_func)"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskSemanticState()
    FlaskRouteCollector(state).collect_from_ast(tree)
    assert len(state.routes) == 1
    assert state.routes[0].path == "/basic"
    assert state.routes[0].handler_name == "my_func"


def test_call_visitor_add_url_rule_methods():
    code = "app.add_url_rule('/m', view_func=fn, methods=['GET', 'POST'])"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskSemanticState()
    FlaskRouteCollector(state).collect_from_ast(tree)
    assert set(state.routes[0].methods) == {"GET", "POST"}


def test_call_visitor_add_url_rule_endpoint():
    code = "app.add_url_rule('/ep', endpoint='custom_ep', view_func=fn)"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskSemanticState()
    FlaskRouteCollector(state).collect_from_ast(tree)
    assert state.routes[0].endpoint == "custom_ep"


def test_call_visitor_add_url_rule_as_view():
    code = "app.add_url_rule('/view', view_func=UserView.as_view('user_view'))"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskSemanticState()
    FlaskRouteCollector(state).collect_from_ast(tree)
    assert state.routes[0].handler_name == "UserView"


def test_call_visitor_add_url_rule_positional_args():
    code = "app.add_url_rule('/pos', 'pos_endpoint', pos_func)"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskSemanticState()
    FlaskRouteCollector(state).collect_from_ast(tree)
    assert state.routes[0].path == "/pos"


def test_call_visitor_add_url_rule_evidence():
    code = "app.add_url_rule('/ev', view_func=fn)"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskSemanticState()
    FlaskRouteCollector(state).collect_from_ast(tree)
    assert "add_url_rule" in state.routes[0].evidence[0]


def test_call_visitor_factory_nested_routes():
    code = """
def create_app():
    app = Flask(__name__)
    @app.route('/factory_route')
    def f_route(): pass
    return app
"""
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskSemanticState()
    FlaskRouteCollector(state).collect_from_ast(tree)
    assert len(state.routes) == 1
    assert state.routes[0].path == "/factory_route"


def test_call_visitor_add_url_rule_attr_handler():
    code = "app.add_url_rule('/attr', view_func=views.my_view)"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskSemanticState()
    FlaskRouteCollector(state).collect_from_ast(tree)
    assert state.routes[0].handler_name == "views.my_view"


def test_call_visitor_add_url_rule_missing_args():
    code = "app.add_url_rule()"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskSemanticState()
    FlaskRouteCollector(state).collect_from_ast(tree)
    assert len(state.routes) == 0


def test_call_visitor_non_add_url_rule_call():
    code = "app.config.from_object('config')"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskSemanticState()
    FlaskRouteCollector(state).collect_from_ast(tree)
    assert len(state.routes) == 0


def test_call_visitor_is_add_url_rule_flag():
    code = "app.add_url_rule('/flag', view_func=fn)"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskSemanticState()
    FlaskRouteCollector(state).collect_from_ast(tree)
    assert state.routes[0].is_add_url_rule is True


def test_call_visitor_add_url_rule_default_method():
    code = "app.add_url_rule('/def', view_func=fn)"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskSemanticState()
    FlaskRouteCollector(state).collect_from_ast(tree)
    assert state.routes[0].methods == ("GET",)


def test_call_visitor_add_url_rule_multiple():
    code = """
app.add_url_rule('/r1', view_func=fn1)
app.add_url_rule('/r2', view_func=fn2)
"""
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskSemanticState()
    collector = FlaskRouteCollector(state)
    collector.collect_from_ast(tree)
    assert len(state.routes) == 2


# ============================================================================
# 6. Decorator Aliases, Assignments & Wrappers Tests (15 tests)
# ============================================================================


def test_decorator_aliases_fixture(extractor: FlaskRouteExtractor):
    fixture_path = FixtureLoader.get_fixture_path("flask/decorator_aliases.py")
    ctx = ExtractorContext(project_path=str(fixture_path), language="Python", framework="FLASK")
    result = extractor.extract(ctx)

    ISRAssertions.assert_valid_isr(result.isr)
    assert len(result.isr.routes) == 2
    FrameworkAssertions.assert_route_exists(result.isr, "/aliased-route", method="GET")
    FrameworkAssertions.assert_route_exists(result.isr, "/shortcut-alias", method="GET")


def test_decorator_resolver_direct_assignment():
    code = "r = app.route"
    tree = PythonASTAdapter.parse_code(code)
    assert tree is not None
    state = FlaskSemanticState()
    FlaskDecoratorResolver(state).visit(tree.children[0])
    assert state.aliases["r"] == "app.route"


def test_decorator_resolver_chained_alias():
    state = FlaskSemanticState()
    state.add_alias("r1", "app.route")
    state.add_alias("r2", "r1")
    target = state.resolve_decorator_target("r2")
    assert target == "app.route"


def test_decorator_resolver_confidence_reduction():
    code = """
route_var = app.route
@route_var('/aliased')
def aliased_fn(): pass
"""
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskSemanticState()
    FlaskRouteCollector(state).collect_from_ast(tree)
    assert len(state.routes) == 1
    assert state.routes[0].path == "/aliased"
    assert state.routes[0].confidence == 0.85


def test_decorator_resolver_shortcut_alias():
    code = "my_post = app.post"
    tree = PythonASTAdapter.parse_code(code)
    assert tree is not None
    state = FlaskSemanticState()
    FlaskDecoratorResolver(state).visit(tree.children[0])
    assert state.aliases["my_post"] == "app.post"


def test_decorator_resolver_non_route_assignment():
    code = "x = 10"
    tree = PythonASTAdapter.parse_code(code)
    assert tree is not None
    state = FlaskSemanticState()
    FlaskDecoratorResolver(state).visit(tree.children[0])
    assert "x" not in state.aliases


def test_decorator_resolver_attribute_assignment():
    code = "my_r = my_app.route"
    tree = PythonASTAdapter.parse_code(code)
    assert tree is not None
    state = FlaskSemanticState()
    FlaskDecoratorResolver(state).visit(tree.children[0])
    assert state.aliases["my_r"] == "my_app.route"


def test_decorator_resolver_circular_alias_safety():
    state = FlaskSemanticState()
    state.add_alias("a", "b")
    state.add_alias("b", "a")
    target = state.resolve_decorator_target("a")
    assert target in ("a", "b")


def test_decorator_resolver_nested_wrappers():
    code = """
@auth.login_required
@permission_check('admin')
@app.route('/secure')
def secure(): pass
"""
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskSemanticState()
    FlaskRouteCollector(state).collect_from_ast(tree)
    assert state.routes[0].path == "/secure"
    assert "login_required" in state.routes[0].decorators


def test_decorator_resolver_unknown_decorator_ignored():
    code = """
@unrelated_dec
def regular_fn(): pass
"""
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskSemanticState()
    FlaskRouteCollector(state).collect_from_ast(tree)
    assert len(state.routes) == 0


def test_decorator_resolver_custom_route_wrapper_fn():
    code = """
def custom_route(path):
    return app.route(path)
"""
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskSemanticState()
    FlaskRouteCollector(state).collect_from_ast(tree)
    assert len(state.routes) == 0


def test_decorator_resolver_multiple_aliases():
    code = """
r1 = app.route
r2 = app.get
"""
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskSemanticState()
    FlaskRouteCollector(state).collect_from_ast(tree)
    assert "r1" in state.aliases
    assert "r2" in state.aliases


def test_decorator_resolver_bp_alias():
    code = "bp_r = bp.route"
    tree = PythonASTAdapter.parse_code(code)
    assert tree is not None
    state = FlaskSemanticState()
    FlaskDecoratorResolver(state).visit(tree.children[0])
    assert state.aliases["bp_r"] == "bp.route"


def test_decorator_resolver_aliased_bp_route():
    code = """
bp_r = bp.route
@bp_r('/aliased_bp')
def aliased_bp_fn(): pass
"""
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskSemanticState()
    FlaskRouteCollector(state).collect_from_ast(tree)
    assert state.routes[0].path == "/aliased_bp"


def test_decorator_resolver_clear_state():
    state = FlaskSemanticState()
    state.add_alias("x", "app.route")
    state.clear()
    assert len(state.aliases) == 0


# ============================================================================
# 7. URL Converter Parameter Extraction Tests (10 tests)
# ============================================================================


def test_url_converters_fixture(extractor: FlaskRouteExtractor):
    fixture_path = FixtureLoader.get_fixture_path("flask/url_converters.py")
    ctx = ExtractorContext(project_path=str(fixture_path), language="Python", framework="FLASK")
    result = extractor.extract(ctx)

    ISRAssertions.assert_valid_isr(result.isr)
    assert len(result.isr.routes) == 4
    FrameworkAssertions.assert_route_exists(result.isr, "/user/{user_id}", method="GET")
    FrameworkAssertions.assert_route_exists(result.isr, "/order/{order_uuid}", method="GET")
    FrameworkAssertions.assert_route_exists(result.isr, "/download/{file_path}", method="GET")
    FrameworkAssertions.assert_route_exists(result.isr, "/greeting/{name}", method="GET")


def test_normalizer_int_converter():
    state = FlaskSemanticState()
    normalizer = FlaskRouteNormalizer(state)
    clean, params = normalizer._parse_url_converters("/user/<int:uid>")
    assert clean == "/user/{uid}"
    assert params == [{"name": "uid", "type": "int"}]


def test_normalizer_uuid_converter():
    state = FlaskSemanticState()
    normalizer = FlaskRouteNormalizer(state)
    clean, params = normalizer._parse_url_converters("/order/<uuid:oid>")
    assert clean == "/order/{oid}"
    assert params == [{"name": "oid", "type": "uuid"}]


def test_normalizer_path_converter():
    state = FlaskSemanticState()
    normalizer = FlaskRouteNormalizer(state)
    clean, params = normalizer._parse_url_converters("/files/<path:p>")
    assert clean == "/files/{p}"
    assert params == [{"name": "p", "type": "path"}]


def test_normalizer_string_converter():
    state = FlaskSemanticState()
    normalizer = FlaskRouteNormalizer(state)
    clean, params = normalizer._parse_url_converters("/item/<string:s>")
    assert clean == "/item/{s}"
    assert params == [{"name": "s", "type": "string"}]


def test_normalizer_implicit_string_converter():
    state = FlaskSemanticState()
    normalizer = FlaskRouteNormalizer(state)
    clean, params = normalizer._parse_url_converters("/user/<username>")
    assert clean == "/user/{username}"
    assert params == [{"name": "username", "type": "string"}]


def test_normalizer_float_converter():
    state = FlaskSemanticState()
    normalizer = FlaskRouteNormalizer(state)
    clean, params = normalizer._parse_url_converters("/price/<float:val>")
    assert clean == "/price/{val}"
    assert params == [{"name": "val", "type": "float"}]


def test_normalizer_multiple_converters():
    state = FlaskSemanticState()
    normalizer = FlaskRouteNormalizer(state)
    clean, params = normalizer._parse_url_converters("/user/<int:uid>/order/<uuid:oid>")
    assert clean == "/user/{uid}/order/{oid}"
    assert len(params) == 2


def test_normalizer_no_converters():
    state = FlaskSemanticState()
    normalizer = FlaskRouteNormalizer(state)
    clean, params = normalizer._parse_url_converters("/static/about")
    assert clean == "/static/about"
    assert len(params) == 0


def test_normalizer_converter_in_route_definition():
    state = FlaskSemanticState()
    state.routes.append(RawRouteRecord(path="/cat/<int:cid>", handler_name="cat"))
    normalizer = FlaskRouteNormalizer(state)
    routes = normalizer.normalize(state.routes)
    assert routes[0].path == "/cat/{cid}"


# ============================================================================
# 8. Multi-File Project Extraction Tests (10 tests)
# ============================================================================


def test_project_basic_app(extractor: FlaskRouteExtractor):
    p_path = FixtureLoader.get_fixture_path("flask/projects/basic_app")
    ctx = ExtractorContext(project_path=str(p_path), language="Python", framework="FLASK")
    res = extractor.extract(ctx)

    ISRAssertions.assert_valid_isr(res.isr)
    assert len(res.isr.routes) == 2
    FrameworkAssertions.assert_route_exists(res.isr, "/", method="GET")
    FrameworkAssertions.assert_route_exists(res.isr, "/about", method="GET")


def test_project_blueprint_app(extractor: FlaskRouteExtractor):
    p_path = FixtureLoader.get_fixture_path("flask/projects/blueprint_app")
    ctx = ExtractorContext(project_path=str(p_path), language="Python", framework="FLASK")
    res = extractor.extract(ctx)

    ISRAssertions.assert_valid_isr(res.isr)
    assert len(res.isr.routes) == 2
    FrameworkAssertions.assert_route_exists(res.isr, "/auth/login", method="POST")
    FrameworkAssertions.assert_route_exists(res.isr, "/api/v1/status", method="GET")


def test_project_factory_app(extractor: FlaskRouteExtractor):
    p_path = FixtureLoader.get_fixture_path("flask/projects/factory_app")
    ctx = ExtractorContext(project_path=str(p_path), language="Python", framework="FLASK")
    res = extractor.extract(ctx)

    ISRAssertions.assert_valid_isr(res.isr)
    assert len(res.isr.routes) == 1
    FrameworkAssertions.assert_route_exists(res.isr, "/ping", method="GET")


def test_project_large_app(extractor: FlaskRouteExtractor):
    p_path = FixtureLoader.get_fixture_path("flask/projects/large_app")
    ctx = ExtractorContext(project_path=str(p_path), language="Python", framework="FLASK")
    res = extractor.extract(ctx)

    ISRAssertions.assert_valid_isr(res.isr)
    assert len(res.isr.routes) == 2
    FrameworkAssertions.assert_route_exists(res.isr, "/users/profile/{user_id}", method="GET")
    FrameworkAssertions.assert_route_exists(res.isr, "/dashboard", method="GET")


def test_project_non_existent_path(extractor: FlaskRouteExtractor):
    ctx = ExtractorContext(project_path="/non/existent/project/dir", language="Python", framework="FLASK")
    res = extractor.extract(ctx)
    assert len(res.isr.routes) == 0


def test_project_single_file_path(extractor: FlaskRouteExtractor):
    p_path = FixtureLoader.get_fixture_path("flask/basic_routes.py")
    ctx = ExtractorContext(project_path=str(p_path), language="Python", framework="FLASK")
    res = extractor.extract(ctx)
    assert len(res.isr.routes) == 4


def test_project_multiple_ast_nodes(extractor: FlaskRouteExtractor):
    code1 = "@app.route('/a')\ndef a(): pass"
    code2 = "@app.route('/b')\ndef b(): pass"
    t1 = PythonASTAdapter.parse_code(code1, "a.py")
    t2 = PythonASTAdapter.parse_code(code2, "b.py")
    ctx = ExtractorContext(ast_nodes=[t1, t2], language="Python", framework="FLASK")
    res = extractor.extract(ctx)
    assert len(res.isr.routes) == 2


def test_project_statistics_population(extractor: FlaskRouteExtractor):
    code = "@app.route('/s')\ndef s(): pass"
    t = PythonASTAdapter.parse_code(code)
    ctx = ExtractorContext(ast_nodes=[t], language="Python", framework="FLASK")
    res = extractor.extract(ctx)
    assert res.statistics.get("routes_count") == 1


def test_project_duplicate_route_warning_logging(extractor: FlaskRouteExtractor):
    code = """
@app.route('/dup')
def dup1(): pass

@app.route('/dup')
def dup2(): pass
"""
    t = PythonASTAdapter.parse_code(code)
    ctx = ExtractorContext(ast_nodes=[t], language="Python", framework="FLASK")
    res = extractor.extract(ctx)
    assert len(res.isr.routes) == 2


def test_project_empty_ast_nodes(extractor: FlaskRouteExtractor):
    ctx = ExtractorContext(ast_nodes=[], language="Python", framework="FLASK")
    res = extractor.extract(ctx)
    assert len(res.isr.routes) == 0


# ============================================================================
# 9. ISR Validation & Evidence Schema Tests (5 tests)
# ============================================================================


def test_route_definition_schema_fields():
    r = RouteDefinition(
        path="/test",
        method="GET",
        handler="test_fn",
        language="Python",
        framework="FLASK",
    )
    assert r.path == "/test"
    assert r.method == "GET"
    assert r.schema_version == "1.0"
    assert r.confidence == 1.0
    assert r.semantic_id != ""


def test_route_definition_origin_evidence():
    code = "@app.route('/ev_check')\ndef ev_check(): pass"
    t = PythonASTAdapter.parse_code(code)
    state = FlaskSemanticState()
    FlaskRouteCollector(state).collect_from_ast(t)
    norm = FlaskRouteNormalizer(state)
    routes = norm.normalize(state.routes)

    assert routes[0].origin is not None
    assert len(routes[0].origin.evidence_list) > 0


def test_route_definition_equality():
    r1 = RouteDefinition(path="/eq", method="GET", handler="fn", framework="FLASK")
    r2 = RouteDefinition(path="/eq", method="GET", handler="fn", framework="FLASK")
    assert r1 == r2


def test_route_definition_json_serializable():
    r = RouteDefinition(path="/json", method="POST", handler="fn", framework="FLASK")
    d = r.to_dict()
    assert d["path"] == "/json"
    assert d["method"] == "POST"


def test_route_definition_from_dict_roundtrip():
    r = RouteDefinition(path="/round", method="GET", handler="fn", framework="FLASK")
    d = r.to_dict()
    r2 = RouteDefinition.from_dict(d)
    assert r.path == r2.path
    assert r.method == r2.method
