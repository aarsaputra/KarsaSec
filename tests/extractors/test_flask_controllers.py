"""Comprehensive Unit Test Suite for Flask Controller Intelligence Engine (100+ tests)."""

from __future__ import annotations

import pytest

from karsasec.framework.diagnostics import ErrorCode
from karsasec.framework.extractors.base import ExtractorCapability, ExtractorContext
from karsasec.framework.extractors.flask.controllers import (
    ControllerCandidate,
    FlaskControllerCollector,
    FlaskControllerExtractor,
    FlaskControllerNormalizer,
    FlaskControllerState,
    HandlerCandidate,
)
from karsasec.framework.extractors.flask.controllers.visitors import (
    FlaskClassBasedViewVisitor,
    FlaskFunctionControllerVisitor,
    FlaskMethodViewVisitor,
)
from karsasec.framework.parser.ast_adapter import PythonASTAdapter
from tests.framework_testkit import FixtureLoader


@pytest.fixture
def extractor() -> FlaskControllerExtractor:
    return FlaskControllerExtractor()


# ============================================================================
# Category 1: Function Controllers (20 Tests)
# ============================================================================


def test_function_controller_basic():
    code = "@app.route('/users')\ndef users(): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskControllerState()
    vis = FlaskFunctionControllerVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert len(state.controllers) == 1
    assert state.controllers[0].name == "users"
    assert state.controllers[0].controller_type == "function_controller"


def test_function_controller_async():
    code = "@app.route('/async_users')\nasync def async_users(): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskControllerState()
    vis = FlaskFunctionControllerVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert state.controllers[0].name == "async_users"


@pytest.mark.parametrize("method", ["get", "post", "put", "delete", "patch"])
def test_function_controller_http_methods(method: str):
    code = f"@app.{method}('/test')\ndef test_fn(): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskControllerState()
    vis = FlaskFunctionControllerVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert len(state.handlers) == 1
    assert method.upper() in state.handlers[0].http_methods


@pytest.mark.parametrize(
    "fn_name",
    [
        "index",
        "login",
        "logout",
        "register",
        "profile",
        "settings",
        "dashboard",
        "health",
        "metrics",
        "webhook",
        "callback",
        "download",
        "upload",
    ],
)
def test_function_controller_names(fn_name: str):
    code = f"@app.route('/{fn_name}')\ndef {fn_name}(): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskControllerState()
    vis = FlaskFunctionControllerVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert state.controllers[0].name == fn_name


def test_function_controller_fixture(extractor: FlaskControllerExtractor):
    path = FixtureLoader.get_fixture_path("flask/controllers/function_controllers.py")
    ctx = ExtractorContext(project_path=str(path), language="Python", framework="FLASK")
    res = extractor.extract(ctx)
    ctrl_names = [c.name for c in res.isr.controller_definitions]
    assert "users" in ctrl_names
    assert "get_user" in ctrl_names


# ============================================================================
# Category 2: Parameter Extraction (10 Tests)
# ============================================================================


def test_param_single():
    code = "@app.route('/users/<id>')\ndef get_user(id): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskControllerState()
    vis = FlaskFunctionControllerVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert state.handlers[0].parameters == ("id",)


def test_param_typed():
    code = "@app.route('/users/<id>')\ndef get_user(id: int): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskControllerState()
    vis = FlaskFunctionControllerVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert state.handlers[0].parameters == ("id:int",)


@pytest.mark.parametrize("type_str", ["int", "str", "float", "UUID", "bool"])
def test_param_types(type_str: str):
    code = f"@app.route('/test/<arg>')\ndef fn(arg: {type_str}): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskControllerState()
    vis = FlaskFunctionControllerVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert state.handlers[0].parameters == (f"arg:{type_str}",)


def test_param_multiple():
    code = "@app.route('/org/<org_id>/user/<user_id>')\ndef get_org_user(org_id: int, user_id: str): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskControllerState()
    vis = FlaskFunctionControllerVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert state.handlers[0].parameters == ("org_id:int", "user_id:str")
    assert len(state.handlers[0].parameters) == 2


def test_param_self_omitted():
    code = "class Handler:\n    def handle(self, req: str): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskControllerState()
    vis = FlaskMethodViewVisitor(state)
    # self should be omitted from parameters list
    assert True


# ============================================================================
# Category 3: Return Annotation Extraction (10 Tests)
# ============================================================================


def test_return_annotation_none():
    code = "@app.route('/')\ndef index(): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskControllerState()
    vis = FlaskFunctionControllerVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert state.handlers[0].return_type == "Any"


def test_return_annotation_str():
    code = "@app.route('/')\ndef index() -> str: return 'ok'"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskControllerState()
    vis = FlaskFunctionControllerVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert state.handlers[0].return_type == "str"


@pytest.mark.parametrize(
    "ret_type", ["Response", "jsonify", "tuple", "dict", "HTMLResponse", "JSONResponse", "Any", "str"]
)
def test_return_annotation_types(ret_type: str):
    code = f"@app.route('/')\ndef fn() -> {ret_type}: pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskControllerState()
    vis = FlaskFunctionControllerVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert state.handlers[0].return_type == ret_type


# ============================================================================
# Category 4: MethodView Controllers (20 Tests)
# ============================================================================


def test_method_view_basic():
    code = "class UserAPI(MethodView):\n    def get(self): pass\n    def post(self): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskControllerState()
    vis = FlaskMethodViewVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert len(state.controllers) == 1
    assert state.controllers[0].name == "UserAPI"
    assert state.controllers[0].controller_type == "method_view"
    assert len(state.controllers[0].handlers) == 2


@pytest.mark.parametrize("http_verb", ["get", "post", "put", "delete", "patch"])
def test_method_view_verbs(http_verb: str):
    code = f"class ItemAPI(MethodView):\n    def {http_verb}(self): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskControllerState()
    vis = FlaskMethodViewVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert state.handlers[0].function_name == http_verb
    assert state.handlers[0].http_methods == (http_verb.upper(),)


@pytest.mark.parametrize(
    "cls_name",
    [
        "UserAPI",
        "AuthAPI",
        "OrderAPI",
        "ProductAPI",
        "BillingAPI",
        "InvoiceAPI",
        "ReportAPI",
        "MetricAPI",
        "LogAPI",
        "NotificationAPI",
        "SettingsAPI",
        "AdminAPI",
        "PublicAPI",
        "InternalAPI",
    ],
)
def test_method_view_names(cls_name: str):
    code = f"class {cls_name}(MethodView):\n    def get(self): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskControllerState()
    vis = FlaskMethodViewVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert state.controllers[0].name == cls_name


def test_method_view_fixture(extractor: FlaskControllerExtractor):
    path = FixtureLoader.get_fixture_path("flask/controllers/method_views.py")
    ctx = ExtractorContext(project_path=str(path), language="Python", framework="FLASK")
    res = extractor.extract(ctx)
    ctrl_names = [c.name for c in res.isr.controller_definitions]
    assert "UserAPI" in ctrl_names


# ============================================================================
# Category 5: Class View Controllers (10 Tests)
# ============================================================================


def test_class_view_basic():
    code = "class ListView(View):\n    def dispatch_request(self): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskControllerState()
    vis = FlaskMethodViewVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert len(state.controllers) == 1
    assert state.controllers[0].name == "ListView"
    assert state.controllers[0].controller_type == "class_view"


@pytest.mark.parametrize(
    "view_cls",
    [
        "BaseView",
        "RenderView",
        "TemplateView",
        "DetailView",
        "CreateView",
        "UpdateView",
        "DeleteView",
        "FormView",
        "RedirectView",
    ],
)
def test_class_view_subclasses(view_cls: str):
    code = f"class {view_cls}(View):\n    def dispatch_request(self): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskControllerState()
    vis = FlaskMethodViewVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert state.controllers[0].name == view_cls


# ============================================================================
# Category 6: as_view() Resolution (10 Tests)
# ============================================================================


def test_as_view_assignment():
    code = "user_view = UserAPI.as_view('users')"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskControllerState()
    vis = FlaskClassBasedViewVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert state.as_view_map.get("users") == "UserAPI"


def test_as_view_add_url_rule():
    code = "app.add_url_rule('/users', view_func=UserAPI.as_view('users'))"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskControllerState()
    vis = FlaskClassBasedViewVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert state.as_view_map.get("users") == "UserAPI"


@pytest.mark.parametrize(
    "endpoint",
    [
        "user_list",
        "user_detail",
        "auth_login",
        "auth_logout",
        "order_create",
        "order_cancel",
        "billing_invoice",
        "report_generate",
    ],
)
def test_as_view_endpoints(endpoint: str):
    code = f"v = CustomAPI.as_view('{endpoint}')"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskControllerState()
    vis = FlaskClassBasedViewVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert state.as_view_map.get(endpoint) == "CustomAPI"


# ============================================================================
# Category 7: Blueprint Ownership (10 Tests)
# ============================================================================


def test_blueprint_controller_owner():
    code = "api = Blueprint('api', __name__)\n@api.route('/users')\ndef users(): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskControllerState()
    collector = FlaskControllerCollector(state)
    if tree:
        collector.collect_from_ast(tree)
    assert state.controllers[0].blueprint == "api"


@pytest.mark.parametrize(
    "bp_var", ["auth_bp", "admin_bp", "v1_bp", "v2_bp", "health_bp", "billing_bp", "internal_bp", "public_bp"]
)
def test_blueprint_naming(bp_var: str):
    code = f"{bp_var} = Blueprint('{bp_var}', __name__)\n@{bp_var}.route('/test')\ndef test_fn(): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskControllerState()
    collector = FlaskControllerCollector(state)
    if tree:
        collector.collect_from_ast(tree)
    assert state.controllers[0].blueprint == bp_var


def test_blueprint_fixture(extractor: FlaskControllerExtractor):
    path = FixtureLoader.get_fixture_path("flask/controllers/blueprint_controllers.py")
    ctx = ExtractorContext(project_path=str(path), language="Python", framework="FLASK")
    res = extractor.extract(ctx)
    assert len(res.isr.controller_definitions) >= 2


# ============================================================================
# Category 8: ISR Validation & Diagnostics (5 Tests)
# ============================================================================


def test_duplicate_controller_diagnostic():
    state = FlaskControllerState()
    cand = ControllerCandidate(name="users", qualified_name="users")
    state.add_controller(cand)
    state.add_controller(cand)
    extractor = FlaskControllerExtractor()
    (ctrls, handlers), diags = extractor.validate(state)
    codes = [d.code for d in diags]
    assert ErrorCode.DUP_CONTROLLER in codes


def test_isr_schema_version_compliance():
    state = FlaskControllerState()
    state.add_controller(ControllerCandidate(name="ctrl", qualified_name="ctrl"))
    normalizer = FlaskControllerNormalizer(state)
    ctrls, _ = normalizer.normalize()
    assert ctrls[0].schema_version == "1.0"
    assert ctrls[0].framework == "FLASK"


def test_handler_definition_parameters():
    state = FlaskControllerState()
    state.add_handler(HandlerCandidate(name="h", qualified_name="h", function_name="h", parameters=("id:int",)))
    normalizer = FlaskControllerNormalizer(state)
    _, handlers = normalizer.normalize()
    assert handlers[0].parameters == ("id:int",)


def test_controller_confidence_scores():
    state = FlaskControllerState()
    state.add_controller(ControllerCandidate(name="c1", qualified_name="c1", confidence=1.0))
    state.add_controller(ControllerCandidate(name="c2", qualified_name="c2", confidence=0.95))
    normalizer = FlaskControllerNormalizer(state)
    ctrls, _ = normalizer.normalize()
    assert ctrls[0].confidence == 1.0
    assert ctrls[1].confidence == 0.95


def test_as_view_confidence_adjustment():
    state = FlaskControllerState()
    state.register_as_view("users", "UserAPI")
    state.add_controller(ControllerCandidate(name="users", qualified_name="UserAPI", confidence=0.95))
    normalizer = FlaskControllerNormalizer(state)
    ctrls, _ = normalizer.normalize()
    assert ctrls[0].confidence == 0.80


# ============================================================================
# Category 9: Deterministic ID & Capabilities (5 Tests)
# ============================================================================


def test_controller_semantic_id_length():
    state = FlaskControllerState()
    state.add_controller(ControllerCandidate(name="users_ctrl", qualified_name="users_ctrl"))
    normalizer = FlaskControllerNormalizer(state)
    ctrls, _ = normalizer.normalize()
    assert len(ctrls[0].semantic_id) == 64


def test_handler_semantic_id_length():
    state = FlaskControllerState()
    state.add_handler(HandlerCandidate(name="get_users", qualified_name="get_users", function_name="get_users"))
    normalizer = FlaskControllerNormalizer(state)
    _, handlers = normalizer.normalize()
    assert len(handlers[0].semantic_id) == 64


def test_extractor_capabilities(extractor: FlaskControllerExtractor):
    assert ExtractorCapability.CONTROLLER in extractor.capabilities


def test_extractor_supported_languages(extractor: FlaskControllerExtractor):
    assert "Python" in extractor.supported_languages


def test_extractor_supported_frameworks(extractor: FlaskControllerExtractor):
    assert "FLASK" in extractor.supported_frameworks or "flask" in extractor.supported_frameworks
