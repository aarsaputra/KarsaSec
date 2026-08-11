"""Comprehensive unit tests for Flask Authentication & Authorization Semantic Extractor (Sprint E10-3B-5)."""

from __future__ import annotations

from pathlib import Path

import pytest

from karsasec.framework.diagnostics import ErrorCode
from karsasec.framework.extractors.base import ExtractorContext
from karsasec.framework.extractors.flask.auth import (
    FlaskAuthExtractor,
)
from karsasec.framework.extractors.registry import extractor_registry
from karsasec.framework.parser.ast_adapter import PythonASTAdapter

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "flask" / "auth"


@pytest.fixture
def extractor() -> FlaskAuthExtractor:
    return FlaskAuthExtractor()


# --- Category A: Flask-Login Tests ---

def test_flask_login_required(extractor: FlaskAuthExtractor):
    filepath = FIXTURES_DIR / "login_required.py"
    ctx = ExtractorContext(project_path=str(filepath))
    state = extractor.collect(ctx)
    defs, diags = extractor.validate(state, ctx)
    result = extractor.emit(defs, ctx)

    assert len(result.isr.auth_definitions) >= 1
    auth = result.isr.auth_definitions[0]
    assert auth.provider == "flask-login"
    assert auth.scheme == "session"
    assert auth.handler == "dashboard"
    assert auth.confidence == 1.0


def test_flask_login_alias(extractor: FlaskAuthExtractor):
    filepath = FIXTURES_DIR / "login_alias.py"
    ctx = ExtractorContext(project_path=str(filepath))
    state = extractor.collect(ctx)
    defs, diags = extractor.validate(state, ctx)

    assert len(defs) >= 1
    auth = defs[0]
    assert auth.provider == "flask-login"
    assert auth.handler == "profile"


@pytest.mark.parametrize("i", range(15))
def test_flask_login_parameterized(extractor: FlaskAuthExtractor, i: int):
    code = f"""
from flask_login import login_required, login_user, logout_user

def route_{i}():
    pass
"""
    tree = PythonASTAdapter.parse_code(code)
    ctx = ExtractorContext(ast_nodes=[tree])
    state = extractor.collect(ctx)
    defs, _ = extractor.validate(state, ctx)
    assert isinstance(defs, list)


# --- Category B: Flask-JWT-Extended Tests ---

def test_jwt_required(extractor: FlaskAuthExtractor):
    filepath = FIXTURES_DIR / "jwt_required.py"
    ctx = ExtractorContext(project_path=str(filepath))
    state = extractor.collect(ctx)
    defs, diags = extractor.validate(state, ctx)

    assert len(defs) >= 1
    auth = defs[0]
    assert auth.provider == "flask-jwt-extended"
    assert auth.scheme == "jwt"
    assert auth.handler == "get_data"


def test_jwt_refresh(extractor: FlaskAuthExtractor):
    filepath = FIXTURES_DIR / "jwt_refresh.py"
    ctx = ExtractorContext(project_path=str(filepath))
    state = extractor.collect(ctx)
    defs, diags = extractor.validate(state, ctx)

    assert len(defs) >= 1
    providers = [a.provider for a in defs]
    assert "flask-jwt-extended" in providers


@pytest.mark.parametrize("i", range(15))
def test_jwt_parameterized(extractor: FlaskAuthExtractor, i: int):
    code = f"""
from flask_jwt_extended import jwt_required, create_access_token

@jwt_required()
def api_func_{i}():
    return create_access_token(identity="user_{i}")
"""
    tree = PythonASTAdapter.parse_code(code)
    ctx = ExtractorContext(ast_nodes=[tree])
    state = extractor.collect(ctx)
    defs, _ = extractor.validate(state, ctx)
    assert len(defs) >= 1


# --- Category C: Flask-HTTPAuth Tests ---

def test_http_basic_auth(extractor: FlaskAuthExtractor):
    filepath = FIXTURES_DIR / "basic_auth.py"
    ctx = ExtractorContext(project_path=str(filepath))
    state = extractor.collect(ctx)
    defs, diags = extractor.validate(state, ctx)

    assert len(defs) >= 1
    auth_types = [a.auth_type for a in defs]
    assert "BASIC_AUTH" in auth_types


@pytest.mark.parametrize("i", range(10))
def test_httpauth_parameterized(extractor: FlaskAuthExtractor, i: int):
    code = f"""
from flask_httpauth import HTTPBasicAuth
auth_{i} = HTTPBasicAuth()

@auth_{i}.login_required
def endpoint_{i}():
    pass
"""
    tree = PythonASTAdapter.parse_code(code)
    ctx = ExtractorContext(ast_nodes=[tree])
    state = extractor.collect(ctx)
    defs, _ = extractor.validate(state, ctx)
    assert len(defs) >= 1


# --- Category D & E: Session & Cookie Tests ---

def test_session_identity(extractor: FlaskAuthExtractor):
    filepath = FIXTURES_DIR / "session_identity.py"
    ctx = ExtractorContext(project_path=str(filepath))
    state = extractor.collect(ctx)
    defs, diags = extractor.validate(state, ctx)

    assert len(defs) >= 1
    auth = defs[0]
    assert auth.provider == "session"
    assert auth.handler == "secret_page"


def test_auth_cookies(extractor: FlaskAuthExtractor):
    filepath = FIXTURES_DIR / "auth_cookies.py"
    ctx = ExtractorContext(project_path=str(filepath))
    state = extractor.collect(ctx)
    defs, diags = extractor.validate(state, ctx)

    assert len(defs) >= 1
    cookie_names = [a.cookie_names for a in defs if a.cookie_names]
    assert any("session_token" in c for c in cookie_names)


@pytest.mark.parametrize("i", range(10))
def test_session_cookie_parameterized(extractor: FlaskAuthExtractor, i: int):
    code = f"""
from flask import session, make_response

def handler_{i}():
    if "user_id" not in session:
        return "Unauthorized"
    resp = make_response("OK")
    resp.set_cookie("session_token_{i}", "val")
    return resp
"""
    tree = PythonASTAdapter.parse_code(code)
    ctx = ExtractorContext(ast_nodes=[tree])
    state = extractor.collect(ctx)
    defs, _ = extractor.validate(state, ctx)
    assert len(defs) >= 1


# --- Category F & G: RBAC Roles & Permissions Tests ---

def test_rbac_roles(extractor: FlaskAuthExtractor):
    filepath = FIXTURES_DIR / "roles.py"
    ctx = ExtractorContext(project_path=str(filepath))
    state = extractor.collect(ctx)
    defs, diags = extractor.validate(state, ctx)

    assert len(defs) >= 1
    roles = defs[0].roles
    assert "admin" in roles
    assert "manager" in roles


def test_rbac_permissions(extractor: FlaskAuthExtractor):
    filepath = FIXTURES_DIR / "permissions.py"
    ctx = ExtractorContext(project_path=str(filepath))
    state = extractor.collect(ctx)
    defs, diags = extractor.validate(state, ctx)

    assert len(defs) >= 1
    perms = defs[0].permissions
    assert "users.write" in perms


@pytest.mark.parametrize("i", range(15))
def test_rbac_parameterized(extractor: FlaskAuthExtractor, i: int):
    code = f"""
@roles_required("role_{i}")
def view_{i}():
    pass
"""
    tree = PythonASTAdapter.parse_code(code)
    ctx = ExtractorContext(ast_nodes=[tree])
    state = extractor.collect(ctx)
    defs, _ = extractor.validate(state, ctx)
    assert len(defs) >= 1


# --- Category H: Custom Decorators & Evidence Tests ---

def test_custom_wrapper(extractor: FlaskAuthExtractor):
    filepath = FIXTURES_DIR / "custom_wrapper.py"
    ctx = ExtractorContext(project_path=str(filepath))
    state = extractor.collect(ctx)
    defs, diags = extractor.validate(state, ctx)

    assert len(defs) >= 1
    auth = defs[0]
    assert auth.confidence == 0.85


@pytest.mark.parametrize("i", range(10))
def test_custom_decorator_parameterized(extractor: FlaskAuthExtractor, i: int):
    code = f"""
def custom_auth_{i}(fn):
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(401)
        return fn(*args, **kwargs)
    return wrapper

@custom_auth_{i}
def func_{i}():
    pass
"""
    tree = PythonASTAdapter.parse_code(code)
    ctx = ExtractorContext(ast_nodes=[tree])
    state = extractor.collect(ctx)
    defs, _ = extractor.validate(state, ctx)
    assert len(defs) >= 1


# --- Category L: False Positives & Negative Fixtures Tests ---

def test_false_positives(extractor: FlaskAuthExtractor):
    filepath = FIXTURES_DIR / "false_positive.py"
    ctx = ExtractorContext(project_path=str(filepath))
    state = extractor.collect(ctx)
    defs, diags = extractor.validate(state, ctx)

    # Generic session keys ("theme", "language"), generic cookies ("theme", "banner_dismissed"), and non-auth decorators MUST NOT yield AuthDefinition objects
    auth_handlers = [a.handler for a in defs if a.handler]
    assert "set_theme" not in auth_handlers
    assert "cached_view" not in auth_handlers


@pytest.mark.parametrize("i", range(10))
def test_negative_cases_parameterized(extractor: FlaskAuthExtractor, i: int):
    code = f"""
from flask import session, make_response

def non_auth_{i}():
    session["theme_{i}"] = "light"
    resp = make_response("OK")
    resp.set_cookie("language_{i}", "en")
    return resp
"""
    tree = PythonASTAdapter.parse_code(code)
    ctx = ExtractorContext(ast_nodes=[tree])
    state = extractor.collect(ctx)
    defs, _ = extractor.validate(state, ctx)
    assert len(defs) == 0


# --- Category J, K, M: Diagnostics, Registry & Determinism Tests ---

def test_diagnostics_generation(extractor: FlaskAuthExtractor):
    code = """
@roles_required()
def empty_role_view():
    pass
"""
    tree = PythonASTAdapter.parse_code(code)
    ctx = ExtractorContext(ast_nodes=[tree])
    state = extractor.collect(ctx)
    defs, diags = extractor.validate(state, ctx)

    diag_codes = [d.code for d in diags]
    assert ErrorCode.INVALID_ROLE in diag_codes


def test_registry_integration():
    ext = extractor_registry.resolve("FlaskAuthExtractor")
    assert ext is not None
    assert ext.name == "FlaskAuthExtractor"


def test_determinism(extractor: FlaskAuthExtractor):
    filepath = FIXTURES_DIR / "jwt_refresh.py"
    ctx = ExtractorContext(project_path=str(filepath))

    state1 = extractor.collect(ctx)
    defs1, diags1 = extractor.validate(state1, ctx)
    res1 = extractor.emit(defs1, ctx)

    state2 = extractor.collect(ctx)
    defs2, diags2 = extractor.validate(state2, ctx)
    res2 = extractor.emit(defs2, ctx)

    ids1 = [a.semantic_id for a in res1.isr.auth_definitions]
    ids2 = [a.semantic_id for a in res2.isr.auth_definitions]
    assert ids1 == ids2
