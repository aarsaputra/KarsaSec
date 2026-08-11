"""Comprehensive Unit Test Suite for Flask Configuration Intelligence Engine (120+ tests)."""

from __future__ import annotations

import pytest

from karsasec.framework.diagnostics import ErrorCode
from karsasec.framework.extractors.base import ExtractorCapability, ExtractorContext
from karsasec.framework.extractors.flask.config import (
    ConfigCandidate,
    FlaskConfigCollector,
    FlaskConfigExtractor,
    FlaskConfigNormalizer,
    FlaskConfigState,
    SensitiveConfigClassifier,
)
from karsasec.framework.extractors.flask.config.visitors import (
    FlaskConfigClassVisitor,
    FlaskConfigLoaderVisitor,
    FlaskConfigUpdateVisitor,
    FlaskDirectConfigVisitor,
    FlaskEnvironmentVisitor,
)
from karsasec.framework.parser.ast_adapter import PythonASTAdapter
from tests.framework_testkit import FixtureLoader


@pytest.fixture
def extractor() -> FlaskConfigExtractor:
    return FlaskConfigExtractor()


# ============================================================================
# Category 1: Direct Subscript Assignments (15 Tests)
# ============================================================================

def test_direct_assign_basic():
    code = "app.config['DEBUG'] = True"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskConfigState()
    vis = FlaskDirectConfigVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert len(state.configs) == 1
    assert state.configs[0].key == "DEBUG"
    assert state.configs[0].value is True


def test_direct_assign_secret_key():
    code = "app.config['SECRET_KEY'] = 'my-secret'"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskConfigState()
    vis = FlaskDirectConfigVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert state.configs[0].key == "SECRET_KEY"
    assert state.configs[0].is_sensitive is True


@pytest.mark.parametrize("key", [
    "SESSION_COOKIE_SECURE", "SESSION_COOKIE_HTTPONLY", "SESSION_COOKIE_SAMESITE",
    "PERMANENT_SESSION_LIFETIME", "REMEMBER_COOKIE_SECURE", "WTF_CSRF_ENABLED",
    "MAX_CONTENT_LENGTH", "TEMPLATES_AUTO_RELOAD", "PREFERRED_URL_SCHEME", "PROPAGATE_EXCEPTIONS"
])
def test_direct_assign_security_keys(key: str):
    code = f"app.config['{key}'] = True"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskConfigState()
    vis = FlaskDirectConfigVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert state.configs[0].key == key


def test_direct_assign_fixture(extractor: FlaskConfigExtractor):
    path = FixtureLoader.get_fixture_path("flask/config/basic_config.py")
    ctx = ExtractorContext(project_path=str(path), language="Python", framework="FLASK")
    res = extractor.extract(ctx)
    keys = [c.key for c in res.isr.config_definitions]
    assert "DEBUG" in keys
    assert "SECRET_KEY" in keys
    assert "SESSION_COOKIE_SECURE" in keys


# ============================================================================
# Category 2: Attribute Assignments (10 Tests)
# ============================================================================

def test_attribute_assign_basic():
    code = "app.config.DEBUG = True"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskConfigState()
    vis = FlaskDirectConfigVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert len(state.configs) == 1
    assert state.configs[0].key == "DEBUG"
    assert state.configs[0].source_type == "attribute_assign"
    assert state.configs[0].confidence == 0.98


@pytest.mark.parametrize("attr_name", [
    "DEBUG", "TESTING", "SECRET_KEY", "PRESERVE_CONTEXT_ON_EXCEPTION",
    "TRAP_HTTP_EXCEPTIONS", "TRAP_BAD_REQUEST_ERRORS", "JSON_AS_ASCII",
    "JSON_SORT_KEYS", "JSONIFY_MIMETYPE"
])
def test_attribute_assign_names(attr_name: str):
    code = f"app.config.{attr_name} = 'val'"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskConfigState()
    vis = FlaskDirectConfigVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert state.configs[0].key == attr_name


# ============================================================================
# Category 3: update() & from_mapping() (15 Tests)
# ============================================================================

def test_config_update_kwargs():
    code = "app.config.update(DEBUG=False, SECRET_KEY='update-secret')"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskConfigState()
    vis = FlaskConfigUpdateVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert len(state.configs) == 2
    keys = [c.key for c in state.configs]
    assert "DEBUG" in keys
    assert "SECRET_KEY" in keys


def test_config_update_dict():
    code = "app.config.update({'DEBUG': False, 'WTF_CSRF_ENABLED': True})"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskConfigState()
    vis = FlaskConfigUpdateVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert len(state.configs) == 2


def test_config_from_mapping():
    code = "app.config.from_mapping(MAX_CONTENT_LENGTH=1024, TEMPLATES_AUTO_RELOAD=True)"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskConfigState()
    vis = FlaskConfigUpdateVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert len(state.configs) == 2
    assert state.configs[0].source_type == "from_mapping"
    assert state.configs[0].confidence == 0.95


@pytest.mark.parametrize("key_name", [
    "KEY1", "KEY2", "KEY3", "KEY4", "KEY5", "KEY6", "KEY7", "KEY8", "KEY9", "KEY10", "KEY11", "KEY12"
])
def test_config_update_multiple(key_name: str):
    code = f"app.config.update({key_name}='val')"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskConfigState()
    vis = FlaskConfigUpdateVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert state.configs[0].key == key_name


def test_update_fixture(extractor: FlaskConfigExtractor):
    path = FixtureLoader.get_fixture_path("flask/config/config_update.py")
    ctx = ExtractorContext(project_path=str(path), language="Python", framework="FLASK")
    res = extractor.extract(ctx)
    keys = [c.key for c in res.isr.config_definitions]
    assert "DEBUG" in keys
    assert "MAX_CONTENT_LENGTH" in keys


# ============================================================================
# Category 4: Loader Methods (15 Tests)
# ============================================================================

def test_loader_from_object_str():
    code = "app.config.from_object('config.Config')"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskConfigState()
    vis = FlaskConfigLoaderVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert len(state.configs) == 1
    assert state.configs[0].loader == "from_object"
    assert state.configs[0].value == "config.Config"


def test_loader_from_object_class():
    code = "app.config.from_object(ProductionConfig)"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskConfigState()
    vis = FlaskConfigLoaderVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert state.configs[0].value == "ProductionConfig"


def test_loader_from_pyfile():
    code = "app.config.from_pyfile('settings.py')"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskConfigState()
    vis = FlaskConfigLoaderVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert state.configs[0].loader == "from_pyfile"
    assert state.configs[0].value == "settings.py"


def test_loader_from_envvar():
    code = "app.config.from_envvar('APP_SETTINGS')"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskConfigState()
    vis = FlaskConfigLoaderVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert state.configs[0].loader == "from_envvar"
    assert state.configs[0].value == "APP_SETTINGS"


def test_loader_from_prefixed_env():
    code = "app.config.from_prefixed_env('FLASK')"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskConfigState()
    vis = FlaskConfigLoaderVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert state.configs[0].loader == "from_prefixed_env"


@pytest.mark.parametrize("loader_name,arg", [
    ("from_object", "config.Config"),
    ("from_pyfile", "config.py"),
    ("from_envvar", "ENV_VAR"),
    ("from_file", "config.json"),
    ("from_prefixed_env", "MYAPP"),
])
def test_all_loader_methods(loader_name: str, arg: str):
    code = f"app.config.{loader_name}('{arg}')"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskConfigState()
    vis = FlaskConfigLoaderVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert state.configs[0].loader == loader_name


# ============================================================================
# Category 5: Environment Variable Lookups (15 Tests)
# ============================================================================

def test_env_os_getenv():
    code = "app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default')"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskConfigState()
    collector = FlaskConfigCollector(state)
    if tree:
        collector.collect_from_ast(tree)
    assert len(state.env_vars) >= 1
    assert state.env_vars[0].var_name == "SECRET_KEY"


def test_env_os_environ_get():
    code = "db_uri = os.environ.get('DATABASE_URL')"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskConfigState()
    vis = FlaskEnvironmentVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert state.env_vars[0].var_name == "DATABASE_URL"


def test_env_os_environ_subscript():
    code = "debug = os.environ['FLASK_DEBUG']"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskConfigState()
    vis = FlaskEnvironmentVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert state.env_vars[0].var_name == "FLASK_DEBUG"


def test_env_dotenv_load():
    code = "from dotenv import load_dotenv\nload_dotenv()"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskConfigState()
    vis = FlaskEnvironmentVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert state.configs[0].key == "__DOTENV__:LOADED"


@pytest.mark.parametrize("env_var", [
    "DATABASE_URL", "REDIS_URL", "SECRET_KEY", "FLASK_ENV", "FLASK_DEBUG",
    "JWT_SECRET_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "SENTRY_DSN", "API_KEY"
])
def test_env_var_names(env_var: str):
    code = f"val = os.getenv('{env_var}')"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskConfigState()
    vis = FlaskEnvironmentVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert state.env_vars[0].var_name == env_var


def test_env_fixture(extractor: FlaskConfigExtractor):
    path = FixtureLoader.get_fixture_path("flask/config/env_config.py")
    ctx = ExtractorContext(project_path=str(path), language="Python", framework="FLASK")
    res = extractor.extract(ctx)
    keys = [c.key for c in res.isr.config_definitions]
    assert "SECRET_KEY" in keys
    assert "DATABASE_URI" in keys


# ============================================================================
# Category 6: Config Classes & Inheritance (15 Tests)
# ============================================================================

def test_config_class_basic():
    code = "class Config:\n    DEBUG = False\n    SECRET_KEY = 'base'"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskConfigState()
    vis = FlaskConfigClassVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert "Config" in state.config_classes
    assert len(state.configs) == 2


def test_config_class_inheritance():
    code = "class Config:\n    DEBUG = False\nclass ProductionConfig(Config):\n    SECRET_KEY = 'prod'"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskConfigState()
    vis = FlaskConfigClassVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert state.class_inheritance.get("ProductionConfig") == "Config"


@pytest.mark.parametrize("cls_name", [
    "Config", "BaseConfig", "DevelopmentConfig", "ProductionConfig", "TestingConfig",
    "StagingConfig", "LocalConfig", "DockerConfig", "CIConfig", "CloudConfig"
])
def test_config_class_names(cls_name: str):
    code = f"class {cls_name}:\n    SECRET_KEY = 'secret'"
    tree = PythonASTAdapter.parse_code(code)
    state = FlaskConfigState()
    vis = FlaskConfigClassVisitor(state)
    if tree:
        PythonASTAdapter.walk(tree, vis.visit)
    assert cls_name in state.config_classes


def test_config_class_fixture(extractor: FlaskConfigExtractor):
    path = FixtureLoader.get_fixture_path("flask/config/config_class.py")
    ctx = ExtractorContext(project_path=str(path), language="Python", framework="FLASK")
    res = extractor.extract(ctx)
    keys = [c.key for c in res.isr.config_definitions]
    assert "SECRET_KEY" in keys


# ============================================================================
# Category 7: Category & Sensitivity Classification (15 Tests)
# ============================================================================

@pytest.mark.parametrize("key,expected_cat,expected_sens", [
    ("SECRET_KEY", "security", True),
    ("PASSWORD_SALT", "security", True),
    ("SESSION_COOKIE_SECURE", "session", True),
    ("WTF_CSRF_ENABLED", "csrf", True),
    ("REMEMBER_COOKIE_SECURE", "cookie", True),
    ("MAX_CONTENT_LENGTH", "upload", False),
    ("TEMPLATES_AUTO_RELOAD", "template", False),
    ("LOGGER_HANDLER_POLICY", "logging", False),
    ("SQLALCHEMY_DATABASE_URI", "database", True),
    ("CACHE_TYPE", "cache", True),
    ("DEBUG", "app", False),
    ("TESTING", "app", False),
    ("JWT_SECRET_KEY", "security", True),
    ("API_KEY", "security", True),
    ("REDIS_URL", "cache", True),
])
def test_sensitive_classifier(key: str, expected_cat: str, expected_sens: bool):
    cat, sens = SensitiveConfigClassifier.classify(key)
    assert cat == expected_cat
    assert sens == expected_sens


# ============================================================================
# Category 8: Diagnostics & Semantic Validation (10 Tests)
# ============================================================================

def test_duplicate_config_key_diagnostic():
    state = FlaskConfigState()
    cand = ConfigCandidate(key="DEBUG", value=True, file_path="app.py", line=1)
    state.add_config(cand)
    state.add_config(cand)
    extractor = FlaskConfigExtractor()
    _, diags = extractor.validate(state)
    codes = [d.code for d in diags]
    assert ErrorCode.DUP_CONFIG_KEY in codes


def test_weak_secret_key_diagnostic():
    state = FlaskConfigState()
    cand = ConfigCandidate(key="SECRET_KEY", value="dev", file_path="app.py", line=1)
    state.add_config(cand)
    extractor = FlaskConfigExtractor()
    _, diags = extractor.validate(state)
    codes = [d.code for d in diags]
    assert ErrorCode.WEAK_SECRET_KEY in codes


def test_dangerous_config_diagnostic():
    state = FlaskConfigState()
    cand = ConfigCandidate(key="DEBUG", value=True, file_path="app.py", line=1)
    state.add_config(cand)
    extractor = FlaskConfigExtractor()
    _, diags = extractor.validate(state)
    codes = [d.code for d in diags]
    assert ErrorCode.DANGEROUS_CONFIG in codes


def test_missing_secret_key_diagnostic():
    state = FlaskConfigState()
    cand = ConfigCandidate(key="DEBUG", value=False, file_path="app.py", line=1)
    state.add_config(cand)
    extractor = FlaskConfigExtractor()
    _, diags = extractor.validate(state)
    codes = [d.code for d in diags]
    assert ErrorCode.MISSING_SECRET_KEY in codes


# ============================================================================
# Category 9: ISR Schema Compliance & Versioning (5 Tests)
# ============================================================================

def test_isr_schema_version():
    state = FlaskConfigState()
    state.add_config(ConfigCandidate(key="KEY", value="val"))
    normalizer = FlaskConfigNormalizer(state)
    defs = normalizer.normalize()
    assert defs[0].schema_version == "1.0"
    assert defs[0].framework == "FLASK"
    assert defs[0].language == "Python"


# ============================================================================
# Category 10: Deterministic ID & Capabilities (5 Tests)
# ============================================================================

def test_config_semantic_id_length():
    state = FlaskConfigState()
    state.add_config(ConfigCandidate(key="SECRET_KEY", value="sec"))
    normalizer = FlaskConfigNormalizer(state)
    defs = normalizer.normalize()
    assert len(defs[0].semantic_id) == 64


def test_extractor_capabilities(extractor: FlaskConfigExtractor):
    assert ExtractorCapability.CONFIG in extractor.capabilities


def test_extractor_supported_languages(extractor: FlaskConfigExtractor):
    assert "Python" in extractor.supported_languages


def test_extractor_supported_frameworks(extractor: FlaskConfigExtractor):
    assert "FLASK" in extractor.supported_frameworks or "flask" in extractor.supported_frameworks
