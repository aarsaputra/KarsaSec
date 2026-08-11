"""Comprehensive Unit Test Suite for Flask Middleware Semantic Extraction Engine (100+ tests)."""

from __future__ import annotations

import pytest

from karsasec.framework.diagnostics import ErrorCode
from karsasec.framework.extractors.base import ExtractorContext
from karsasec.framework.extractors.flask.middleware import (
    FlaskMiddlewareCollector,
    FlaskMiddlewareExtractor,
    FlaskMiddlewareNormalizer,
    FlaskMiddlewareState,
)
from karsasec.framework.extractors.flask.middleware.state import (
    ExtensionCandidate,
    MiddlewareCandidate,
)
from karsasec.framework.extractors.flask.middleware.visitors import (
    FlaskAfterRequestVisitor,
    FlaskBeforeRequestVisitor,
    FlaskClassMiddlewareVisitor,
    FlaskErrorHandlerVisitor,
    FlaskExtensionVisitor,
    FlaskTeardownVisitor,
)
from karsasec.framework.parser.ast_adapter import PythonASTAdapter
from tests.framework_testkit import FixtureLoader


@pytest.fixture
def extractor() -> FlaskMiddlewareExtractor:
    return FlaskMiddlewareExtractor()


# ============================================================================
# Category 1: Before Request Hooks (15 Tests)
# ============================================================================

def test_before_request_basic():
    code = "@app.before_request\ndef auth(): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskMiddlewareState()
    FlaskBeforeRequestVisitor(state).visit(tree.children[0] if tree else None)
    assert len(state.middleware_candidates) == 1
    assert state.middleware_candidates[0].handler == "auth"
    assert state.middleware_candidates[0].middleware_type == "BEFORE_REQUEST"


def test_before_request_async():
    code = "@app.before_request\nasync def async_auth(): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskMiddlewareState()
    FlaskBeforeRequestVisitor(state).visit(tree.children[0] if tree else None)
    assert state.middleware_candidates[0].handler == "async_auth"


def test_before_first_request():
    code = "@app.before_first_request\ndef init_db(): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskMiddlewareState()
    FlaskBeforeRequestVisitor(state).visit(tree.children[0] if tree else None)
    assert state.middleware_candidates[0].handler == "init_db"


def test_before_request_module_attribute():
    code = "@flask_app.before_request\ndef check(): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskMiddlewareState()
    FlaskBeforeRequestVisitor(state).visit(tree.children[0] if tree else None)
    assert state.middleware_candidates[0].name == "flask_app.check"


@pytest.mark.parametrize("fn_name", ["auth_check", "validate_session", "rate_limit", "log_ip", "verify_csrf"])
def test_before_request_param_functions(fn_name: str):
    code = f"@app.before_request\ndef {fn_name}(): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskMiddlewareState()
    FlaskBeforeRequestVisitor(state).visit(tree.children[0] if tree else None)
    assert state.middleware_candidates[0].handler == fn_name


def test_before_request_multiple_decorators():
    code = "@custom_dec\n@app.before_request\ndef multi(): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskMiddlewareState()
    FlaskBeforeRequestVisitor(state).visit(tree.children[0] if tree else None)
    assert len(state.middleware_candidates) == 1
    assert state.middleware_candidates[0].handler == "multi"


def test_before_request_confidence():
    code = "@app.before_request\ndef fn(): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskMiddlewareState()
    FlaskBeforeRequestVisitor(state).visit(tree.children[0] if tree else None)
    assert state.middleware_candidates[0].confidence == 1.0


def test_before_request_fixture(extractor: FlaskMiddlewareExtractor):
    path = FixtureLoader.get_fixture_path("flask/middleware/basic_middleware.py")
    ctx = ExtractorContext(project_path=str(path), language="Python", framework="FLASK")
    res = extractor.extract(ctx)
    mw_names = [m.name for m in res.isr.middleware_definitions]
    assert any("authenticate" in name for name in mw_names)


# ============================================================================
# Category 2: After Request Hooks (10 Tests)
# ============================================================================

def test_after_request_basic():
    code = "@app.after_request\ndef add_headers(resp): return resp"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskMiddlewareState()
    FlaskAfterRequestVisitor(state).visit(tree.children[0] if tree else None)
    assert len(state.middleware_candidates) == 1
    assert state.middleware_candidates[0].handler == "add_headers"
    assert state.middleware_candidates[0].phase == "after_response"


def test_after_request_async():
    code = "@app.after_request\nasync def async_headers(resp): return resp"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskMiddlewareState()
    FlaskAfterRequestVisitor(state).visit(tree.children[0] if tree else None)
    assert state.middleware_candidates[0].handler == "async_headers"


@pytest.mark.parametrize("fn_name", ["set_cookie", "cors_headers", "security_header", "metrics_collector", "audit_log", "compress_response", "flush_session", "timing_header"])
def test_after_request_variations(fn_name: str):
    code = f"@app.after_request\ndef {fn_name}(r): return r"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskMiddlewareState()
    FlaskAfterRequestVisitor(state).visit(tree.children[0] if tree else None)
    assert state.middleware_candidates[0].handler == fn_name


# ============================================================================
# Category 3: Blueprint Middleware (15 Tests)
# ============================================================================

def test_bp_before_request():
    code = "@auth_bp.before_request\ndef bp_auth(): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskMiddlewareState()
    state.register_blueprint("auth_bp", "auth")
    FlaskBeforeRequestVisitor(state).visit(tree.children[0] if tree else None)
    assert state.middleware_candidates[0].blueprint == "auth"
    assert state.middleware_candidates[0].confidence == 0.95


def test_bp_after_request():
    code = "@api_bp.after_request\ndef bp_after(r): return r"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskMiddlewareState()
    state.register_blueprint("api_bp", "api")
    FlaskAfterRequestVisitor(state).visit(tree.children[0] if tree else None)
    assert state.middleware_candidates[0].blueprint == "api"


@pytest.mark.parametrize("bp_var", ["user_bp", "admin_bp", "v1_bp", "v2_bp", "health_bp", "billing_bp", "checkout_bp", "reports_bp", "internal_bp", "webhook_bp", "oauth_bp", "saml_bp", "mfa_bp"])
def test_bp_middleware_naming(bp_var: str):
    code = f"@{bp_var}.before_request\ndef check(): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskMiddlewareState()
    state.register_blueprint(bp_var, bp_var.replace("_bp", ""))
    FlaskBeforeRequestVisitor(state).visit(tree.children[0] if tree else None)
    assert state.middleware_candidates[0].blueprint is not None


# ============================================================================
# Category 4: Error Handlers (15 Tests)
# ============================================================================

def test_errorhandler_status_code_404():
    code = "@app.errorhandler(404)\ndef handle_404(e): return '404', 404"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskMiddlewareState()
    FlaskErrorHandlerVisitor(state).visit(tree.children[0] if tree else None)
    assert len(state.error_handlers) == 1
    assert state.error_handlers[0].status_code == 404
    assert state.error_handlers[0].handler == "handle_404"


def test_errorhandler_status_code_500():
    code = "@app.errorhandler(500)\ndef handle_500(e): return '500', 500"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskMiddlewareState()
    FlaskErrorHandlerVisitor(state).visit(tree.children[0] if tree else None)
    assert state.error_handlers[0].status_code == 500


def test_errorhandler_exception_type():
    code = "@app.errorhandler(ValueError)\ndef handle_val_err(e): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskMiddlewareState()
    FlaskErrorHandlerVisitor(state).visit(tree.children[0] if tree else None)
    assert state.error_handlers[0].exception_type == "ValueError"


@pytest.mark.parametrize("status_code", [400, 401, 403, 404, 405, 408, 429, 500, 502, 503, 504])
def test_errorhandler_status_codes(status_code: int):
    code = f"@app.errorhandler({status_code})\ndef h(e): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskMiddlewareState()
    FlaskErrorHandlerVisitor(state).visit(tree.children[0] if tree else None)
    assert state.error_handlers[0].status_code == status_code


def test_errorhandler_blueprint():
    code = "@bp.errorhandler(403)\ndef bp_403(e): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskMiddlewareState()
    state.register_blueprint("bp", "auth_bp")
    FlaskErrorHandlerVisitor(state).visit(tree.children[0] if tree else None)
    assert state.error_handlers[0].blueprint == "auth_bp"


# ============================================================================
# Category 5: Teardown Hooks (10 Tests)
# ============================================================================

def test_teardown_request():
    code = "@app.teardown_request\ndef cleanup_req(e): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskMiddlewareState()
    FlaskTeardownVisitor(state).visit(tree.children[0] if tree else None)
    assert len(state.middleware_candidates) == 1
    assert state.middleware_candidates[0].phase == "request_teardown"


def test_teardown_appcontext():
    code = "@app.teardown_appcontext\ndef cleanup_ctx(e): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskMiddlewareState()
    FlaskTeardownVisitor(state).visit(tree.children[0] if tree else None)
    assert state.middleware_candidates[0].phase == "application_teardown"


@pytest.mark.parametrize("func_name", ["db_close", "session_remove", "file_close", "temp_cleanup", "metric_flush", "cache_sync", "socket_disconnect", "tracker_close"])
def test_teardown_variations(func_name: str):
    code = f"@app.teardown_request\ndef {func_name}(e): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskMiddlewareState()
    FlaskTeardownVisitor(state).visit(tree.children[0] if tree else None)
    assert state.middleware_candidates[0].handler == func_name


# ============================================================================
# Category 6: Extensions (15 Tests)
# ============================================================================

def test_extension_cors():
    code = "CORS(app)"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskMiddlewareState()
    vis = FlaskExtensionVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert len(state.extensions) == 1
    assert state.extensions[0].extension_name == "CORS"


def test_extension_limiter():
    code = "Limiter(app)"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskMiddlewareState()
    vis = FlaskExtensionVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert state.extensions[0].extension_name == "Limiter"


def test_extension_login_manager():
    code = "LoginManager(app)"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskMiddlewareState()
    vis = FlaskExtensionVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert state.extensions[0].extension_name == "LoginManager"


def test_extension_cache():
    code = "Cache(app)"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskMiddlewareState()
    vis = FlaskExtensionVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert state.extensions[0].extension_name == "Cache"


def test_extension_init_app():
    code = "limiter.init_app(app)"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskMiddlewareState()
    vis = FlaskExtensionVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert len(state.extensions) == 1


@pytest.mark.parametrize("ext_class", ["CORS", "Limiter", "LoginManager", "Cache", "CSRFProtect", "Session", "Bcrypt", "Talisman", "FlaskCors", "FlaskLimiter"])
def test_extension_parametrized(ext_class: str):
    code = f"{ext_class}(app)"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskMiddlewareState()
    vis = FlaskExtensionVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert state.extensions[0].extension_name == ext_class


# ============================================================================
# Category 7: Class Middleware (10 Tests)
# ============================================================================

def test_class_middleware_before():
    code = "class AuthMiddleware:\n    def before_request(self): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskMiddlewareState()
    FlaskClassMiddlewareVisitor(state).visit(tree.children[0] if tree else None)
    assert len(state.class_middlewares) == 1
    assert state.class_middlewares[0].handler == "AuthMiddleware.before_request"


def test_class_middleware_after():
    code = "class HeaderMiddleware:\n    def after_request(self, r): return r"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskMiddlewareState()
    FlaskClassMiddlewareVisitor(state).visit(tree.children[0] if tree else None)
    assert state.class_middlewares[0].phase == "after_response"


@pytest.mark.parametrize("cls_name", ["SecurityMiddleware", "SessionMiddleware", "RateLimitMiddleware", "CorsMiddleware", "TracingMiddleware", "MetricsMiddleware", "AuditMiddleware", "CSRFMiddleware"])
def test_class_middleware_variations(cls_name: str):
    code = f"class {cls_name}:\n    def before_request(self): pass"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskMiddlewareState()
    FlaskClassMiddlewareVisitor(state).visit(tree.children[0] if tree else None)
    assert cls_name in state.class_middlewares[0].name


# ============================================================================
# Category 8: Multi-File Resolution (5 Tests)
# ============================================================================

def test_multi_file_collection():
    code1 = "@app.before_request\ndef f1(): pass"
    code2 = "CORS(app)"
    tree1 = PythonASTAdapter.parse_code(code1)
    tree2 = PythonASTAdapter.parse_code(code2)
    state = FlaskMiddlewareState()
    collector = FlaskMiddlewareCollector(state)
    collector.collect_from_ast(tree1)
    collector.collect_from_ast(tree2)
    assert len(state.middleware_candidates) == 1
    assert len(state.extensions) == 1


def test_multi_file_fixture(extractor: FlaskMiddlewareExtractor):
    path = FixtureLoader.get_fixture_path("flask/middleware/multi_file")
    ctx = ExtractorContext(project_path=str(path), language="Python", framework="FLASK")
    res = extractor.extract(ctx)
    mw_names = [m.name for m in res.isr.middleware_definitions]
    assert any("global_auth_check" in name for name in mw_names)
    assert any("CORS" in name for name in mw_names)


def test_multi_file_collector_empty():
    state = FlaskMiddlewareState()
    collector = FlaskMiddlewareCollector(state)
    collector.collect_from_ast(None)
    assert len(state.middleware_candidates) == 0


def test_multi_file_roots():
    code1 = "@app.before_request\ndef f1(): pass"
    code2 = "@app.after_request\ndef f2(r): return r"
    t1 = PythonASTAdapter.parse_code(code1)
    t2 = PythonASTAdapter.parse_code(code2)
    roots = [t for t in (t1, t2) if t is not None]
    state = FlaskMiddlewareState()
    collector = FlaskMiddlewareCollector(state)
    collector.collect_from_asts(roots)
    assert len(state.middleware_candidates) == 2


def test_multi_file_normalizer_ordering():
    state = FlaskMiddlewareState()
    state.add_middleware_candidate(MiddlewareCandidate(name="m1", middleware_type="BEFORE_REQUEST", handler="f1"))
    state.add_middleware_candidate(MiddlewareCandidate(name="m2", middleware_type="AFTER_REQUEST", handler="f2"))
    normalizer = FlaskMiddlewareNormalizer(state)
    mw_defs = normalizer.normalize()
    assert mw_defs[0].order == 1
    assert mw_defs[1].order == 2


# ============================================================================
# Category 9: ISR Validation & Diagnostics (5 Tests)
# ============================================================================

def test_duplicate_middleware_diagnostic():
    state = FlaskMiddlewareState()
    cand = MiddlewareCandidate(name="a.auth", middleware_type="BEFORE_REQUEST", handler="auth", phase="before_request", decorator="@app.before_request")
    state.add_middleware_candidate(cand)
    state.add_middleware_candidate(cand)
    extractor = FlaskMiddlewareExtractor()
    _, diags = extractor.validate(state)
    codes = [d.code for d in diags]
    assert ErrorCode.DUP_MIDDLEWARE in codes


def test_unknown_extension_diagnostic():
    state = FlaskMiddlewareState()
    ext = ExtensionCandidate(extension_name="CustomUnknownExt", constructor="CustomUnknownExt(app)")
    state.add_extension(ext)
    extractor = FlaskMiddlewareExtractor()
    _, diags = extractor.validate(state)
    codes = [d.code for d in diags]
    assert ErrorCode.UNKNOWN_EXTENSION in codes


def test_invalid_handler_diagnostic():
    state = FlaskMiddlewareState()
    cand = MiddlewareCandidate(name="invalid", middleware_type="BEFORE_REQUEST", handler="", phase="before_request")
    state.add_middleware_candidate(cand)
    extractor = FlaskMiddlewareExtractor()
    _, diags = extractor.validate(state)
    codes = [d.code for d in diags]
    assert ErrorCode.INVALID_MIDDLEWARE_HANDLER in codes


def test_isr_schema_version_compliance():
    state = FlaskMiddlewareState()
    state.add_middleware_candidate(MiddlewareCandidate(name="test_mw", middleware_type="BEFORE_REQUEST", handler="test_mw"))
    normalizer = FlaskMiddlewareNormalizer(state)
    mw_defs = normalizer.normalize()
    assert mw_defs[0].schema_version == "1.0"
    assert mw_defs[0].framework == "FLASK"


def test_middleware_definition_semantic_id():
    state = FlaskMiddlewareState()
    state.add_middleware_candidate(MiddlewareCandidate(name="sec_mw", middleware_type="BEFORE_REQUEST", handler="sec_mw"))
    normalizer = FlaskMiddlewareNormalizer(state)
    mw_defs = normalizer.normalize()
    assert len(mw_defs[0].semantic_id) == 64


def test_middleware_target_routes_wildcard():
    state = FlaskMiddlewareState()
    state.add_middleware_candidate(MiddlewareCandidate(name="global_mw", middleware_type="BEFORE_REQUEST", handler="global_mw"))
    normalizer = FlaskMiddlewareNormalizer(state)
    mw_defs = normalizer.normalize()
    assert mw_defs[0].target_routes == ("*",)


def test_middleware_blueprint_target_routes():
    state = FlaskMiddlewareState()
    state.add_middleware_candidate(MiddlewareCandidate(name="auth.check", middleware_type="BEFORE_REQUEST", handler="check", blueprint="auth"))
    normalizer = FlaskMiddlewareNormalizer(state)
    mw_defs = normalizer.normalize()
    assert mw_defs[0].target_routes == ("auth/*",)


def test_extractor_supported_languages(extractor: FlaskMiddlewareExtractor):
    assert "Python" in extractor.supported_languages


def test_extractor_supported_frameworks(extractor: FlaskMiddlewareExtractor):
    assert "FLASK" in extractor.supported_frameworks or "flask" in extractor.supported_frameworks


def test_extractor_capability(extractor: FlaskMiddlewareExtractor):
    from karsasec.framework.extractors.base import ExtractorCapability
    assert ExtractorCapability.MIDDLEWARE in extractor.capabilities

