"""Unit tests for Framework Extractor Infrastructure (Sprint E10-2B)."""

import pytest

from karsasec.framework.diagnostics import ErrorCode, SemanticDiagnostic, Severity
from karsasec.framework.extractors.base import (
    ExtractionError,
    ExtractionResult,
    ExtractorCapability,
    ExtractorContext,
    SemanticExtractor,
)
from karsasec.framework.extractors.registry import ExtractorRegistry
from karsasec.framework.intermediate import (
    AuthDefinition,
    ControllerDefinition,
    DependencyDefinition,
    HandlerDefinition,
    IntermediateSemanticRepresentation,
    MiddlewareDefinition,
    ModelDefinition,
    RouteDefinition,
)
from karsasec.framework.manifest import CapabilityResolver, FrameworkManifest, ManifestLoader
from karsasec.framework.origin import SourceLocation
from karsasec.framework.pipeline import FrameworkSemanticPipeline
from karsasec.framework.validator import ISRValidator

# ============================================================================
# Dummy Mock Extractors for Testing
# ============================================================================

class MockRouteExtractor(SemanticExtractor):
    @property
    def name(self) -> str:
        return "MockRouteExtractor"

    @property
    def priority(self) -> int:
        return 10

    @property
    def supported_languages(self) -> tuple[str, ...]:
        return ("Python", "Generic")

    @property
    def supported_frameworks(self) -> tuple[str, ...]:
        return ("FLASK", "FASTAPI")

    @property
    def capabilities(self) -> tuple[ExtractorCapability, ...]:
        return (ExtractorCapability.ROUTING,)

    def extract(self, ctx: ExtractorContext) -> ExtractionResult:
        r = RouteDefinition(path="/test", method="GET", handler="test_handler")
        isr = IntermediateSemanticRepresentation(routes=(r,))
        return ExtractionResult(isr=isr)


class MockHandlerExtractor(SemanticExtractor):
    @property
    def name(self) -> str:
        return "MockHandlerExtractor"

    @property
    def priority(self) -> int:
        return 20

    @property
    def supported_languages(self) -> tuple[str, ...]:
        return ("Python", "Generic")

    @property
    def supported_frameworks(self) -> tuple[str, ...]:
        return ("FLASK", "FASTAPI")

    @property
    def capabilities(self) -> tuple[ExtractorCapability, ...]:
        return (ExtractorCapability.CONTROLLER,)

    def extract(self, ctx: ExtractorContext) -> ExtractionResult:
        h = HandlerDefinition(name="test_handler", function_name="test_handler")
        isr = IntermediateSemanticRepresentation(handlers=(h,))
        return ExtractionResult(isr=isr)


class FailingMockExtractor(SemanticExtractor):
    @property
    def name(self) -> str:
        return "FailingMockExtractor"

    def extract(self, ctx: ExtractorContext) -> ExtractionResult:
        raise ExtractionError("Extraction crashed unexpectedly", extractor_name=self.name)


# ============================================================================
# 1. Extractor SDK & Context Tests (1-10)
# ============================================================================

def test_extractor_capability_enum():
    assert ExtractorCapability.ROUTING == "routing"
    assert ExtractorCapability.MIDDLEWARE == "middleware"
    assert ExtractorCapability.ORM == "orm"


def test_extraction_error_exception():
    err = ExtractionError("Failed to parse AST", extractor_name="TestExtractor")
    assert str(err) == "Failed to parse AST"
    assert err.extractor_name == "TestExtractor"


def test_extractor_context_defaults():
    ctx = ExtractorContext()
    assert ctx.project_path == ""
    assert ctx.language == "Generic"
    assert ctx.framework == "GENERIC"
    assert ctx.ast_nodes == []


def test_extractor_context_custom_values():
    ctx = ExtractorContext(project_path="/app", language="Python", framework="FLASK", config={"debug": True})
    assert ctx.project_path == "/app"
    assert ctx.language == "Python"
    assert ctx.framework == "FLASK"
    assert ctx.config["debug"] is True


def test_extraction_result_defaults():
    res = ExtractionResult()
    assert len(res.isr.routes) == 0
    assert len(res.diagnostics) == 0
    assert len(res.warnings) == 0


def test_extraction_result_merge():
    r1 = RouteDefinition(path="/a", method="GET", handler="h1")
    r2 = RouteDefinition(path="/b", method="POST", handler="h2")
    res1 = ExtractionResult(isr=IntermediateSemanticRepresentation(routes=(r1,)), warnings=["w1"])
    res2 = ExtractionResult(isr=IntermediateSemanticRepresentation(routes=(r2,)), warnings=["w2"])

    merged = res1.merge(res2)
    assert len(merged.isr.routes) == 2
    assert merged.isr.routes[0].path == "/a"
    assert merged.isr.routes[1].path == "/b"
    assert merged.warnings == ["w1", "w2"]


def test_semantic_extractor_abc_defaults():
    ext = MockRouteExtractor()
    assert ext.name == "MockRouteExtractor"
    assert ext.priority == 10
    assert ext.dependencies == ()
    assert ext.incremental is True
    assert ext.cacheable is True


def test_semantic_extractor_can_extract_positive():
    ext = MockRouteExtractor()
    ctx = ExtractorContext(language="Python", framework="FLASK")
    assert ext.can_extract(ctx) is True


def test_semantic_extractor_can_extract_generic():
    ext = MockRouteExtractor()
    ctx = ExtractorContext(language="Java", framework="SPRING")
    # Python + Generic in supported languages, FLASK + FASTAPI in frameworks
    assert ext.can_extract(ctx) is False


def test_semantic_extractor_execution():
    ext = MockRouteExtractor()
    ctx = ExtractorContext(language="Python", framework="FLASK")
    res = ext.extract(ctx)
    assert len(res.isr.routes) == 1
    assert res.isr.routes[0].path == "/test"


# ============================================================================
# 2. Diagnostics Engine Tests (11-18)
# ============================================================================

def test_severity_enum():
    assert Severity.ERROR == "ERROR"
    assert Severity.WARNING == "WARNING"
    assert Severity.INFO == "INFO"


def test_error_code_enum():
    assert ErrorCode.DUP_ROUTE == "ERR_SEM_DUP_ROUTE"
    assert ErrorCode.MISSING_HANDLER == "ERR_SEM_MISSING_HANDLER"


def test_semantic_diagnostic_creation():
    loc = SourceLocation(file_path="app.py", line=10)
    diag = SemanticDiagnostic(
        code=ErrorCode.DUP_ROUTE,
        severity=Severity.ERROR,
        message="Duplicate route found",
        location=loc,
        evidence="GET /login",
        remediation="Remove duplicate route",
    )
    assert diag.code == ErrorCode.DUP_ROUTE
    assert diag.severity == Severity.ERROR
    assert diag.message == "Duplicate route found"


def test_semantic_diagnostic_serialization():
    loc = SourceLocation(file_path="app.py", line=10)
    diag = SemanticDiagnostic(
        code=ErrorCode.DUP_HANDLER,
        severity=Severity.WARNING,
        message="Duplicate handler",
        location=loc,
    )
    data = diag.to_dict()
    assert data["code"] == ErrorCode.DUP_HANDLER.value
    assert data["severity"] == Severity.WARNING.value

    diag2 = SemanticDiagnostic.from_dict(data)
    assert diag2 == diag


def test_diagnostic_severity_comparison():
    assert Severity.ERROR.value == "ERROR"
    assert Severity.WARNING.value == "WARNING"


def test_diagnostic_error_code_values():
    assert ErrorCode.DUP_MODEL.value == "ERR_SEM_DUP_MODEL"
    assert ErrorCode.BROKEN_DEP.value == "ERR_SEM_BROKEN_DEP"


def test_diagnostic_default_location():
    diag = SemanticDiagnostic(code=ErrorCode.UNKNOWN_AUTH, severity=Severity.INFO, message="Unknown auth")
    assert diag.location.file_path == ""


def test_diagnostic_remediation_field():
    diag = SemanticDiagnostic(
        code=ErrorCode.ORPHAN_MIDDLEWARE,
        severity=Severity.WARNING,
        message="Orphan mw",
        remediation="Fix path",
    )
    assert diag.remediation == "Fix path"


# ============================================================================
# 3. Manifest Loader & Capability Resolver Tests (19-28)
# ============================================================================

def test_framework_manifest_creation():
    manifest = FrameworkManifest(
        framework="FLASK",
        language="Python",
        capabilities=(ExtractorCapability.ROUTING, ExtractorCapability.CONFIG),
        extractors=("RouteExtractor", "ConfigExtractor"),
    )
    assert manifest.framework == "FLASK"
    assert manifest.capabilities == (ExtractorCapability.ROUTING, ExtractorCapability.CONFIG)


def test_framework_manifest_to_dict_roundtrip():
    manifest = FrameworkManifest(
        framework="FASTAPI",
        language="Python",
        capabilities=(ExtractorCapability.ROUTING,),
        extractors=("FastAPIRouteExtractor",),
    )
    data = manifest.to_dict()
    manifest2 = FrameworkManifest.from_dict(data)
    assert manifest == manifest2


def test_manifest_loader_from_dict():
    raw = {
        "framework": {
            "framework": "EXPRESS",
            "language": "JavaScript",
            "capabilities": ["routing", "middleware"],
            "extractors": ["ExpressRouteExtractor"],
        }
    }
    manifest = ManifestLoader.load_from_dict(raw)
    assert manifest.framework == "EXPRESS"
    assert ExtractorCapability.ROUTING in manifest.capabilities


def test_manifest_loader_from_yaml():
    yaml_content = """
    framework:
      framework: django
      language: python
      capabilities:
        - routing
        - orm
      extractors:
        - DjangoRouteExtractor
        - DjangoORMExtractor
    """
    manifest = ManifestLoader.load_from_yaml(yaml_content)
    assert manifest.framework == "django"
    assert ExtractorCapability.ORM in manifest.capabilities


def test_manifest_loader_file_not_found():
    with pytest.raises(FileNotFoundError):
        ManifestLoader.load_from_file("non_existent_plugin.yaml")


def test_capability_resolver_routing():
    nodes = ["@app.route('/login')", "def login(): pass"]
    caps = CapabilityResolver.resolve_capabilities(nodes)
    assert ExtractorCapability.ROUTING in caps


def test_capability_resolver_middleware():
    nodes = ["app.use(express.json())"]
    caps = CapabilityResolver.resolve_capabilities(nodes)
    assert ExtractorCapability.MIDDLEWARE in caps


def test_capability_resolver_orm():
    nodes = ["class User(db.Model): Column(Integer)"]
    caps = CapabilityResolver.resolve_capabilities(nodes)
    assert ExtractorCapability.ORM in caps


def test_capability_resolver_auth():
    nodes = ["jwt.decode(token, SECRET_KEY)"]
    caps = CapabilityResolver.resolve_capabilities(nodes)
    assert ExtractorCapability.AUTH in caps


def test_capability_resolver_multiple():
    nodes = [
        "@app.route('/login')",
        "jwt.decode(token)",
        "db.Column(Integer)",
    ]
    caps = CapabilityResolver.resolve_capabilities(nodes)
    assert ExtractorCapability.ROUTING in caps
    assert ExtractorCapability.AUTH in caps
    assert ExtractorCapability.ORM in caps


# ============================================================================
# 4. Extractor Registry Tests (29-38)
# ============================================================================

def test_registry_register_and_list():
    reg = ExtractorRegistry()
    ext1 = MockRouteExtractor()
    ext2 = MockHandlerExtractor()

    reg.register(ext1)
    reg.register(ext2)

    l = reg.list()
    assert len(l) == 2
    assert l[0].name == "MockRouteExtractor"
    assert l[1].name == "MockHandlerExtractor"


def test_registry_resolve_by_name():
    reg = ExtractorRegistry()
    ext = MockRouteExtractor()
    reg.register(ext)

    assert reg.resolve("MockRouteExtractor") == ext
    assert reg.resolve("Unknown") is None


def test_registry_unregister():
    reg = ExtractorRegistry()
    ext = MockRouteExtractor()
    reg.register(ext)

    res = reg.unregister("MockRouteExtractor")
    assert res is True
    assert reg.resolve("MockRouteExtractor") is None

    res_fail = reg.unregister("MockRouteExtractor")
    assert res_fail is False


def test_registry_resolve_by_framework():
    reg = ExtractorRegistry()
    ext1 = MockRouteExtractor()
    ext2 = MockHandlerExtractor()
    reg.register(ext1)
    reg.register(ext2)

    resolved = reg.resolve_by_framework("FLASK")
    assert len(resolved) == 2


def test_registry_resolve_by_capability():
    reg = ExtractorRegistry()
    ext1 = MockRouteExtractor()
    ext2 = MockHandlerExtractor()
    reg.register(ext1)
    reg.register(ext2)

    resolved_routing = reg.resolve_by_capability(ExtractorCapability.ROUTING)
    assert len(resolved_routing) == 1
    assert resolved_routing[0].name == "MockRouteExtractor"

    resolved_ctrl = reg.resolve_by_capability("controller")
    assert len(resolved_ctrl) == 1
    assert resolved_ctrl[0].name == "MockHandlerExtractor"


def test_registry_priority_sorting():
    class LowPriorityExtractor(MockRouteExtractor):
        @property
        def name(self) -> str:
            return "LowPriority"

        @property
        def priority(self) -> int:
            return 200

    class HighPriorityExtractor(MockRouteExtractor):
        @property
        def name(self) -> str:
            return "HighPriority"

        @property
        def priority(self) -> int:
            return 5

    reg = ExtractorRegistry()
    reg.register(LowPriorityExtractor())
    reg.register(HighPriorityExtractor())

    l = reg.list()
    assert l[0].name == "HighPriority"
    assert l[1].name == "LowPriority"


def test_registry_clear():
    reg = ExtractorRegistry()
    reg.register(MockRouteExtractor())
    assert len(reg.list()) == 1
    reg.clear()
    assert len(reg.list()) == 0


def test_registry_overwrite_warning(caplog):
    reg = ExtractorRegistry()
    ext1 = MockRouteExtractor()
    ext2 = MockRouteExtractor()

    reg.register(ext1)
    reg.register(ext2)
    assert len(reg.list()) == 1


def test_global_extractor_registry_singleton():
    from karsasec.framework import extractor_registry
    assert isinstance(extractor_registry, ExtractorRegistry)


def test_registry_resolve_empty():
    reg = ExtractorRegistry()
    assert len(reg.resolve_by_framework("UNKNOWN")) == 0


# ============================================================================
# 5. ISR Validator Tests (39-50)
# ============================================================================

def test_validator_clean_isr():
    validator = ISRValidator()
    route = RouteDefinition(path="/a", method="GET", handler="h1")
    handler = HandlerDefinition(name="h1", function_name="h1")
    isr = IntermediateSemanticRepresentation(routes=(route,), handlers=(handler,))

    diags = validator.validate(isr)
    assert len(diags) == 0


def test_validator_duplicate_route():
    validator = ISRValidator()
    r1 = RouteDefinition(path="/login", method="POST", handler="login_h")
    r2 = RouteDefinition(path="/login", method="POST", handler="login_h2")
    h1 = HandlerDefinition(name="login_h", function_name="login_h")
    h2 = HandlerDefinition(name="login_h2", function_name="login_h2")
    isr = IntermediateSemanticRepresentation(routes=(r1, r2), handlers=(h1, h2))

    diags = validator.validate(isr)
    assert len(diags) == 1
    assert diags[0].code == ErrorCode.DUP_ROUTE
    assert diags[0].severity == Severity.ERROR


def test_validator_missing_handler():
    validator = ISRValidator()
    r1 = RouteDefinition(path="/data", method="GET", handler="missing_h")
    isr = IntermediateSemanticRepresentation(routes=(r1,))

    diags = validator.validate(isr)
    assert len(diags) == 1
    assert diags[0].code == ErrorCode.MISSING_HANDLER
    assert diags[0].severity == Severity.WARNING


def test_validator_duplicate_handler():
    validator = ISRValidator()
    h1 = HandlerDefinition(name="process", function_name="process_fn")
    h2 = HandlerDefinition(name="process", function_name="process_fn_2")
    isr = IntermediateSemanticRepresentation(handlers=(h1, h2))

    diags = validator.validate(isr)
    assert len(diags) == 1
    assert diags[0].code == ErrorCode.DUP_HANDLER


def test_validator_missing_controller_handler():
    validator = ISRValidator()
    ctrl = ControllerDefinition(name="UserCtrl", handlers=("non_existent_h",))
    isr = IntermediateSemanticRepresentation(controllers=(ctrl,))

    diags = validator.validate(isr)
    assert len(diags) == 1
    assert diags[0].code == ErrorCode.MISSING_HANDLER


def test_validator_orphan_middleware():
    validator = ISRValidator()
    mw = MiddlewareDefinition(name="AuthMw", scope="route", target_routes=("/non_existent_route",))
    isr = IntermediateSemanticRepresentation(middlewares=(mw,))

    diags = validator.validate(isr)
    assert len(diags) == 1
    assert diags[0].code == ErrorCode.ORPHAN_MIDDLEWARE


def test_validator_duplicate_model():
    validator = ISRValidator()
    m1 = ModelDefinition(model_name="User")
    m2 = ModelDefinition(model_name="User")
    isr = IntermediateSemanticRepresentation(models=(m1, m2))

    diags = validator.validate(isr)
    assert len(diags) == 1
    assert diags[0].code == ErrorCode.DUP_MODEL


def test_validator_broken_dependency():
    validator = ISRValidator()
    dep = DependencyDefinition(dependency_name="db", target_class_or_fn="UnregisteredProvider")
    isr = IntermediateSemanticRepresentation(dependencies=(dep,))

    diags = validator.validate(isr)
    assert len(diags) == 1
    assert diags[0].code == ErrorCode.BROKEN_DEP


def test_validator_unknown_auth():
    validator = ISRValidator()
    auth = AuthDefinition(auth_type="CustomUnrecognizedAuthType")
    isr = IntermediateSemanticRepresentation(auths=(auth,))

    diags = validator.validate(isr)
    assert len(diags) == 1
    assert diags[0].code == ErrorCode.UNKNOWN_AUTH


def test_validator_multiple_errors():
    validator = ISRValidator()
    r1 = RouteDefinition(path="/r", method="GET", handler="h")
    r2 = RouteDefinition(path="/r", method="GET", handler="h")
    h = HandlerDefinition(name="h", function_name="h")
    m1 = ModelDefinition(model_name="M")
    m2 = ModelDefinition(model_name="M")
    isr = IntermediateSemanticRepresentation(routes=(r1, r2), handlers=(h,), models=(m1, m2))

    diags = validator.validate(isr)
    assert len(diags) == 2  # Dup route, dup model


def test_validator_valid_auth_types():
    validator = ISRValidator()
    for auth_str in ["JWT", "OAuth2", "Session", "Cookie", "APIKey", "RBAC"]:
        auth = AuthDefinition(auth_type=auth_str)
        isr = IntermediateSemanticRepresentation(auths=(auth,))
        diags = validator.validate(isr)
        assert len(diags) == 0


def test_validator_orphan_middleware_valid_target():
    validator = ISRValidator()
    r = RouteDefinition(path="/admin", method="GET", handler="admin_h")
    h = HandlerDefinition(name="admin_h", function_name="admin_h")
    mw = MiddlewareDefinition(name="AdminMw", scope="route", target_routes=("/admin",))
    isr = IntermediateSemanticRepresentation(routes=(r,), handlers=(h,), middlewares=(mw,))

    diags = validator.validate(isr)
    assert len(diags) == 0


# ============================================================================
# 6. Framework Semantic Pipeline Tests (51-62)
# ============================================================================

def test_pipeline_execution_with_registered_extractors():
    reg = ExtractorRegistry()
    reg.register(MockRouteExtractor())
    reg.register(MockHandlerExtractor())

    pipeline = FrameworkSemanticPipeline(registry=reg)
    ctx = ExtractorContext(language="Python", framework="FLASK")

    isr, diags = pipeline.run(ctx)
    assert len(isr.routes) == 1
    assert len(isr.handlers) == 1
    assert isr.routes[0].path == "/test"
    assert isr.handlers[0].name == "test_handler"
    assert len(diags) == 0


def test_pipeline_execution_with_manifest_dict():
    reg = ExtractorRegistry()
    reg.register(MockRouteExtractor())

    pipeline = FrameworkSemanticPipeline(registry=reg)
    ctx = ExtractorContext(language="Python", framework="FLASK")
    manifest = {"framework": "FLASK", "extractors": ["MockRouteExtractor"]}

    isr, diags = pipeline.run(ctx, manifest=manifest)
    assert len(isr.routes) == 1


def test_pipeline_execution_with_manifest_yaml():
    reg = ExtractorRegistry()
    reg.register(MockRouteExtractor())

    pipeline = FrameworkSemanticPipeline(registry=reg)
    ctx = ExtractorContext(language="Python", framework="FLASK")
    yaml_spec = """
    framework:
      framework: FLASK
      extractors:
        - MockRouteExtractor
    """

    isr, diags = pipeline.run(ctx, manifest=yaml_spec)
    assert len(isr.routes) == 1


def test_pipeline_execution_with_explicit_extractors():
    pipeline = FrameworkSemanticPipeline()
    ctx = ExtractorContext(language="Python", framework="FLASK")

    isr, diags = pipeline.run(ctx, extractors=[MockRouteExtractor()])
    assert len(isr.routes) == 1


def test_pipeline_handles_failing_extractor():
    reg = ExtractorRegistry()
    reg.register(MockRouteExtractor())
    reg.register(FailingMockExtractor())

    pipeline = FrameworkSemanticPipeline(registry=reg)
    ctx = ExtractorContext(language="Python", framework="FLASK")

    isr, diags = pipeline.run(ctx)
    assert len(isr.routes) == 1


def test_pipeline_validation_triggers_diagnostics():
    class BadRouteExtractor(SemanticExtractor):
        @property
        def name(self) -> str:
            return "BadRouteExtractor"

        def extract(self, ctx: ExtractorContext) -> ExtractionResult:
            r1 = RouteDefinition(path="/dup", method="GET", handler="missing_h")
            r2 = RouteDefinition(path="/dup", method="GET", handler="missing_h")
            return ExtractionResult(isr=IntermediateSemanticRepresentation(routes=(r1, r2)))

    pipeline = FrameworkSemanticPipeline()
    ctx = ExtractorContext(language="Python", framework="FLASK")

    isr, diags = pipeline.run(ctx, extractors=[BadRouteExtractor()])
    assert len(isr.routes) == 2
    assert len(diags) > 0
    assert any(d.code == ErrorCode.DUP_ROUTE for d in diags)


def test_pipeline_empty_extractors():
    pipeline = FrameworkSemanticPipeline()
    ctx = ExtractorContext(language="Unknown", framework="UNKNOWN")

    isr, diags = pipeline.run(ctx)
    assert len(isr.routes) == 0
    assert len(diags) == 0


def test_pipeline_priority_execution_order():
    execution_order = []

    class ExtractorFirst(SemanticExtractor):
        @property
        def name(self) -> str:
            return "First"

        @property
        def priority(self) -> int:
            return 1

        def extract(self, ctx: ExtractorContext) -> ExtractionResult:
            execution_order.append("First")
            return ExtractionResult()

    class ExtractorSecond(SemanticExtractor):
        @property
        def name(self) -> str:
            return "Second"

        @property
        def priority(self) -> int:
            return 99

        def extract(self, ctx: ExtractorContext) -> ExtractionResult:
            execution_order.append("Second")
            return ExtractionResult()

    pipeline = FrameworkSemanticPipeline()
    ctx = ExtractorContext()
    pipeline.run(ctx, extractors=[ExtractorSecond(), ExtractorFirst()])
    assert execution_order == ["First", "Second"]


def test_pipeline_manifest_object_input():
    manifest = FrameworkManifest(framework="FLASK", extractors=("MockRouteExtractor",))
    reg = ExtractorRegistry()
    reg.register(MockRouteExtractor())

    pipeline = FrameworkSemanticPipeline(registry=reg)
    ctx = ExtractorContext(language="Python", framework="FLASK")
    isr, diags = pipeline.run(ctx, manifest=manifest)
    assert len(isr.routes) == 1


def test_pipeline_multiple_diagnostics_accumulation():
    validator = ISRValidator()
    r = RouteDefinition(path="/a", method="GET", handler="h")
    isr_bad = IntermediateSemanticRepresentation(routes=(r,))

    diags = validator.validate(isr_bad)
    assert len(diags) == 1
    assert diags[0].code == ErrorCode.MISSING_HANDLER


def test_extraction_result_statistics_and_telemetry():
    res1 = ExtractionResult(statistics={"count": 1}, telemetry={"time_ms": 12.5})
    res2 = ExtractionResult(statistics={"items": 5}, telemetry={"parse_ms": 4.1})
    merged = res1.merge(res2)

    assert merged.statistics["count"] == 1
    assert merged.statistics["items"] == 5
    assert merged.telemetry["time_ms"] == 12.5
    assert merged.telemetry["parse_ms"] == 4.1


def test_pipeline_logging(caplog):
    import logging
    caplog.set_level(logging.INFO)
    pipeline = FrameworkSemanticPipeline()
    ctx = ExtractorContext(framework="FLASK")
    pipeline.run(ctx)
    assert "Starting FrameworkSemanticPipeline" in caplog.text

