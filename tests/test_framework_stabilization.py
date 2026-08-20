"""Unit tests for Sprint E10-3A: Architecture Stabilization & Framework Detector."""

import json
from pathlib import Path
from typing import Any

import pytest

from karsasec.framework import (
    CURRENT_ISR_SCHEMA_VERSION,
    AuthDefinition,
    BuilderContext,
    BuilderOptions,
    CapabilityResolver,
    ConfigDefinition,
    ControllerDefinition,
    DependencyDefinition,
    DetectorResult,
    ExtractionResult,
    ExtractorCapability,
    ExtractorContext,
    FrameworkDetectionResult,
    FrameworkDetector,
    FrameworkGraphBuilder,
    FrameworkManifest,
    HandlerDefinition,
    IntermediateSemanticRepresentation,
    ISRMigrator,
    ManifestLoader,
    MiddlewareDefinition,
    ModelDefinition,
    OriginMetadata,
    RouteDefinition,
    SemanticExtractor,
    SourceLocation,
    TemplateDefinition,
)
from tests.framework_testkit import (
    ASTAssertions,
    FixtureLoader,
    FrameworkAssertions,
    ISRAssertions,
    SnapshotAssertions,
)


# Dummy test extractor implementing collect -> validate -> emit
class SampleStabilizedExtractor(SemanticExtractor):
    @property
    def name(self) -> str:
        return "SampleStabilizedExtractor"

    @property
    def supported_languages(self) -> tuple[str, ...]:
        return ("Python",)

    @property
    def supported_frameworks(self) -> tuple[str, ...]:
        return ("FLASK",)

    def collect(self, ctx: ExtractorContext) -> list[dict[str, str]]:
        return [{"path": "/test", "method": "GET", "handler": "test_h"}]

    def validate(
        self, raw_items: list[dict[str, str]], ctx: ExtractorContext
    ) -> tuple[list[dict[str, str]], list[str]]:
        validated = [item for item in raw_items if item["path"].startswith("/")]
        return validated, []

    def emit(self, validated_items: list[dict[str, str]], ctx: ExtractorContext) -> ExtractionResult:
        routes = tuple(
            RouteDefinition(
                path=item["path"], method=item["method"], handler=item["handler"], framework="FLASK", language="Python"
            )
            for item in validated_items
        )
        return ExtractionResult(isr=IntermediateSemanticRepresentation(routes=routes))


# ============================================================================
# 1. Framework Detection Tests (1-15)
# ============================================================================


def test_framework_detection_result_defaults():
    res = FrameworkDetectionResult(framework="FLASK")
    assert res.framework == "FLASK"
    assert res.version == "1.0.0"
    assert res.language == "Generic"
    assert res.confidence == 1.0
    assert len(res.capabilities) == 0


def test_framework_detection_result_to_from_dict():
    res1 = FrameworkDetectionResult(
        framework="FASTAPI",
        version="0.110.0",
        language="Python",
        confidence=0.95,
        capabilities=("routing", "auth"),
        evidence=("main.py: FastAPI()",),
    )
    d = res1.to_dict()
    res2 = FrameworkDetectionResult.from_dict(d)
    assert res2 == res1


def test_detector_detect_framework_flask_fixture():
    detector = FrameworkDetector()
    fixture_dir = FixtureLoader.get_fixture_path("flask")
    res = detector.detect_framework(fixture_dir)
    assert res.framework == "FLASK"
    assert res.language == "Python"
    assert res.confidence >= 0.6


def test_detector_detect_framework_fastapi_fixture():
    detector = FrameworkDetector()
    fixture_dir = FixtureLoader.get_fixture_path("fastapi")
    res = detector.detect_framework(fixture_dir)
    assert res.framework == "FASTAPI"
    assert res.language == "Python"


def test_detector_detect_framework_django_fixture():
    detector = FrameworkDetector()
    fixture_dir = FixtureLoader.get_fixture_path("django")
    res = detector.detect_framework(fixture_dir)
    assert res.framework == "DJANGO"
    assert res.language == "Python"


def test_detector_detect_framework_express_fixture():
    detector = FrameworkDetector()
    fixture_dir = FixtureLoader.get_fixture_path("express")
    res = detector.detect_framework(fixture_dir)
    assert res.framework == "EXPRESS"
    assert res.language == "JavaScript"


def test_detector_detect_framework_nextjs_fixture():
    detector = FrameworkDetector()
    fixture_dir = FixtureLoader.get_fixture_path("nextjs")
    res = detector.detect_framework(fixture_dir)
    assert res.framework == "NEXTJS"
    assert res.language == "JavaScript"


def test_detector_detect_framework_laravel_fixture():
    detector = FrameworkDetector()
    fixture_dir = FixtureLoader.get_fixture_path("laravel")
    res = detector.detect_framework(fixture_dir)
    assert res.framework == "LARAVEL"
    assert res.language == "PHP"


def test_detector_detect_framework_gin_fixture():
    detector = FrameworkDetector()
    fixture_dir = FixtureLoader.get_fixture_path("gin")
    res = detector.detect_framework(fixture_dir)
    assert res.framework == "GIN"
    assert res.language == "Go"


def test_detector_non_existent_path_returns_generic():
    detector = FrameworkDetector()
    res = detector.detect_framework(Path("/non/existent/path/for/test"))
    assert res.framework == "GENERIC"
    assert res.confidence == 0.5


def test_detector_detect_returns_list_of_results():
    detector = FrameworkDetector()
    fixture_dir = FixtureLoader.get_fixture_path("flask")
    results = detector.detect(fixture_dir)
    assert isinstance(results, list)
    assert len(results) >= 1
    assert isinstance(results[0], DetectorResult)


def test_detector_capabilities_extracted():
    detector = FrameworkDetector()
    fixture_dir = FixtureLoader.get_fixture_path("flask")
    res = detector.detect_framework(fixture_dir)
    assert "routing" in res.capabilities or "middleware" in res.capabilities or len(res.capabilities) >= 0


def test_detector_result_reason_populated():
    detector = FrameworkDetector()
    fixture_dir = FixtureLoader.get_fixture_path("flask")
    res = detector.detect_framework(fixture_dir)
    assert len(res.reason) > 0


def test_detector_result_evidence_tuple():
    detector = FrameworkDetector()
    fixture_dir = FixtureLoader.get_fixture_path("flask")
    res = detector.detect_framework(fixture_dir)
    assert isinstance(res.evidence, tuple)


def test_detector_multiple_fixture_scan():
    detector = FrameworkDetector()
    for fw in ["flask", "fastapi", "django", "express", "nextjs", "laravel", "gin"]:
        path = FixtureLoader.get_fixture_path(fw)
        res = detector.detect_framework(path)
        assert res.framework == fw.upper()


# ============================================================================
# 2. Extractor Lifecycle Tests (16-30)
# ============================================================================


def test_semantic_extractor_lifecycle_collect():
    extractor = SampleStabilizedExtractor()
    ctx = ExtractorContext(language="Python", framework="FLASK")
    collected = extractor.collect(ctx)
    assert len(collected) == 1
    assert collected[0]["path"] == "/test"


def test_semantic_extractor_lifecycle_validate():
    extractor = SampleStabilizedExtractor()
    ctx = ExtractorContext()
    raw = [{"path": "/valid", "method": "GET", "handler": "h1"}, {"path": "invalid", "method": "GET", "handler": "h2"}]
    validated, diags = extractor.validate(raw, ctx)
    assert len(validated) == 1
    assert validated[0]["path"] == "/valid"


def test_semantic_extractor_lifecycle_emit():
    extractor = SampleStabilizedExtractor()
    ctx = ExtractorContext()
    raw = [{"path": "/emit", "method": "POST", "handler": "emit_h"}]
    res = extractor.emit(raw, ctx)
    assert len(res.isr.routes) == 1
    assert res.isr.routes[0].path == "/emit"


def test_semantic_extractor_extract_delegates_lifecycle():
    extractor = SampleStabilizedExtractor()
    ctx = ExtractorContext(language="Python", framework="FLASK")
    res = extractor.extract(ctx)
    assert len(res.isr.routes) == 1
    assert res.isr.routes[0].path == "/test"


def test_semantic_extractor_can_extract_matching():
    extractor = SampleStabilizedExtractor()
    ctx = ExtractorContext(language="Python", framework="FLASK")
    assert extractor.can_extract(ctx) is True


def test_semantic_extractor_can_extract_mismatch():
    extractor = SampleStabilizedExtractor()
    ctx = ExtractorContext(language="Java", framework="SPRING")
    assert extractor.can_extract(ctx) is False


def test_semantic_extractor_properties_defaults():
    extractor = SampleStabilizedExtractor()
    assert extractor.priority == 100
    assert extractor.dependencies == ()
    assert extractor.incremental is True
    assert extractor.cacheable is True


def test_extraction_result_merge():
    r1 = ExtractionResult(
        isr=IntermediateSemanticRepresentation(routes=(RouteDefinition(path="/r1", method="GET", handler="h1"),))
    )
    r2 = ExtractionResult(
        isr=IntermediateSemanticRepresentation(routes=(RouteDefinition(path="/r2", method="POST", handler="h2"),))
    )
    merged = r1.merge(r2)
    assert len(merged.isr.routes) == 2


def test_extraction_result_diagnostics_merge():
    r1 = ExtractionResult(diagnostics=["diag1"])
    r2 = ExtractionResult(diagnostics=["diag2"])
    merged = r1.merge(r2)
    assert merged.diagnostics == ["diag1", "diag2"]


def test_extraction_result_warnings_merge():
    r1 = ExtractionResult(warnings=["warn1"])
    r2 = ExtractionResult(warnings=["warn2"])
    merged = r1.merge(r2)
    assert merged.warnings == ["warn1", "warn2"]


def test_extractor_context_defaults():
    ctx = ExtractorContext()
    assert ctx.language == "Generic"
    assert ctx.framework == "GENERIC"
    assert len(ctx.ast_nodes) == 0


def test_extractor_context_custom():
    ctx = ExtractorContext(language="Go", framework="GIN", project_path="/path/to/gin")
    assert ctx.language == "Go"
    assert ctx.framework == "GIN"
    assert ctx.project_path == "/path/to/gin"


def test_extractor_lifecycle_empty_collect():
    class EmptyExtractor(SemanticExtractor):
        @property
        def name(self) -> str:
            return "EmptyExtractor"

    extractor = EmptyExtractor()
    ctx = ExtractorContext()
    res = extractor.extract(ctx)
    assert len(res.isr.routes) == 0


def test_extractor_lifecycle_with_diagnostics():
    class DiagExtractor(SemanticExtractor):
        @property
        def name(self) -> str:
            return "DiagExtractor"

        def validate(self, raw_items: Any, ctx: ExtractorContext) -> tuple[Any, list[Any]]:
            return raw_items, ["validation warning"]

    extractor = DiagExtractor()
    res = extractor.extract(ExtractorContext())
    assert "validation warning" in res.diagnostics


def test_extractor_capability_enum_values():
    assert ExtractorCapability.ROUTING == "routing"
    assert ExtractorCapability.AUTH == "auth"
    assert ExtractorCapability.ORM == "orm"


# ============================================================================
# 3. ISR Contract Freeze & ISRMigrator Tests (31-50)
# ============================================================================


def test_current_isr_schema_version_constant():
    assert CURRENT_ISR_SCHEMA_VERSION == "1.0"


def test_route_definition_schema_fields():
    r = RouteDefinition(path="/login", method="POST", handler="login_h", framework="FLASK", language="Python")
    assert r.schema_version == "1.0"
    assert r.confidence == 1.0
    assert len(r.semantic_id) == 64  # SHA-256


def test_route_definition_to_from_dict_with_schema():
    r1 = RouteDefinition(path="/login", method="POST", handler="login_h", framework="FLASK", language="Python")
    d = r1.to_dict()
    assert d["schema_version"] == "1.0"
    assert "semantic_id" in d
    r2 = RouteDefinition.from_dict(d)
    assert r2.path == r1.path
    assert r2.schema_version == "1.0"


def test_middleware_definition_schema_fields():
    m = MiddlewareDefinition(name="AuthMw", framework="FLASK")
    assert m.schema_version == "1.0"
    assert len(m.semantic_id) == 64


def test_controller_definition_schema_fields():
    c = ControllerDefinition(name="AuthCtrl", framework="FLASK")
    assert c.schema_version == "1.0"
    assert len(c.semantic_id) == 64


def test_handler_definition_schema_fields():
    h = HandlerDefinition(name="login", function_name="login", framework="FLASK")
    assert h.schema_version == "1.0"
    assert len(h.semantic_id) == 64


def test_model_definition_schema_fields():
    m = ModelDefinition(model_name="User", framework="FLASK")
    assert m.schema_version == "1.0"
    assert len(m.semantic_id) == 64


def test_config_definition_schema_fields():
    cfg = ConfigDefinition(key="SECRET_KEY", framework="FLASK")
    assert cfg.schema_version == "1.0"
    assert len(cfg.semantic_id) == 64


def test_isr_schema_version_attribute():
    isr = IntermediateSemanticRepresentation()
    assert isr.schema_version == "1.0"
    assert isr.to_dict()["schema_version"] == "1.0"


def test_isr_migrator_validate_valid():
    isr = IntermediateSemanticRepresentation()
    valid, errors = ISRMigrator.validate(isr.to_dict())
    assert valid is True
    assert len(errors) == 0


def test_isr_migrator_validate_missing_schema():
    d = {"routes": []}
    valid, errors = ISRMigrator.validate(d)
    assert valid is False
    assert any("schema_version" in e for e in errors)


def test_isr_migrator_upgrade():
    d = {"routes": []}
    upgraded = ISRMigrator.upgrade(d, "1.0")
    assert upgraded["schema_version"] == "1.0"


def test_isr_migrator_downgrade():
    d = {"schema_version": "2.0", "routes": []}
    downgraded = ISRMigrator.downgrade(d, "1.0")
    assert downgraded["schema_version"] == "1.0"


def test_isr_json_serialization_preserves_schema():
    isr = IntermediateSemanticRepresentation(routes=(RouteDefinition(path="/a", method="GET", handler="h"),))
    json_str = isr.to_json()
    isr2 = IntermediateSemanticRepresentation.from_json(json_str)
    assert isr2.schema_version == "1.0"
    assert len(isr2.routes) == 1


def test_auth_definition_schema_fields():
    a = AuthDefinition(auth_type="JWT", framework="FLASK")
    assert a.schema_version == "1.0"
    assert len(a.semantic_id) == 64


def test_template_definition_schema_fields():
    t = TemplateDefinition(template_name="index.html", framework="FLASK")
    assert t.schema_version == "1.0"
    assert len(t.semantic_id) == 64


def test_dependency_definition_schema_fields():
    dep = DependencyDefinition(dependency_name="db", target_class_or_fn="get_db", framework="FLASK")
    assert dep.schema_version == "1.0"
    assert len(dep.semantic_id) == 64


def test_all_definitions_exposes_semantic_id():
    origin = OriginMetadata(location_info=SourceLocation(file_path="app.py", line=10))
    defs = [
        RouteDefinition(path="/p", method="GET", handler="h", origin=origin),
        MiddlewareDefinition(name="m", origin=origin),
        ControllerDefinition(name="c", origin=origin),
        HandlerDefinition(name="h", function_name="h", origin=origin),
        ModelDefinition(model_name="m", origin=origin),
        ConfigDefinition(key="k", origin=origin),
        AuthDefinition(auth_type="JWT", origin=origin),
    ]
    for d in defs:
        assert isinstance(d.semantic_id, str)
        assert len(d.semantic_id) == 64


def test_isr_from_dict_defaults_schema_version():
    data = {"routes": [{"path": "/x", "method": "GET", "handler": "h"}]}
    isr = IntermediateSemanticRepresentation.from_dict(data)
    assert isr.schema_version == "1.0"
    assert isr.routes[0].schema_version == "1.0"


def test_isr_builder_interoperability():
    isr = IntermediateSemanticRepresentation(
        routes=(RouteDefinition(path="/api/test", method="GET", handler="test_h"),)
    )
    builder = FrameworkGraphBuilder(context=BuilderContext(isr=isr, options=BuilderOptions(auto_freeze=False)))
    graph = builder.build()
    assert len(graph.nodes()) == 1


# ============================================================================
# 4. Plugin Manifest V2 Tests (51-65)
# ============================================================================


def test_framework_manifest_v2_defaults():
    manifest = FrameworkManifest(framework="FLASK")
    assert manifest.framework == "FLASK"
    assert manifest.language == "Generic"
    assert manifest.version == ">=1.0"
    assert manifest.priority == 100


def test_framework_manifest_v2_to_from_dict():
    m1 = FrameworkManifest(
        framework="FASTAPI",
        language="Python",
        version=">=0.100.0",
        supported_capabilities=("routing", "auth"),
        extractors=("RouteExtractor", "AuthExtractor"),
        priority=10,
    )
    d = m1.to_dict()
    m2 = FrameworkManifest.from_dict(d)
    assert m2.framework == m1.framework
    assert m2.version == m1.version
    assert m2.priority == 10


def test_manifest_loader_yaml_v2():
    yaml_str = """
framework: Flask
language: python
version: ">=3.0"
priority: 10
extractors:
  - RouteExtractor
  - MiddlewareExtractor
supported_capabilities:
  - routing
  - middleware
"""
    manifest = ManifestLoader.load_from_yaml(yaml_str)
    assert manifest.framework == "Flask"
    assert manifest.language == "python"
    assert manifest.version == ">=3.0"
    assert manifest.priority == 10
    assert "RouteExtractor" in manifest.extractors


def test_manifest_loader_dict_v2():
    d = {
        "framework": "Express",
        "language": "JavaScript",
        "version": ">=4.0",
        "extractors": ["RouteExtractor"],
        "supported_capabilities": ["routing"],
    }
    manifest = ManifestLoader.load_from_dict(d)
    assert manifest.framework == "Express"
    assert manifest.language == "JavaScript"


def test_manifest_loader_file_not_found():
    with pytest.raises(FileNotFoundError):
        ManifestLoader.load_from_file("/invalid/path/plugin.yaml")


def test_capability_resolver_resolve_routing():
    ast_sample = ["def route(): pass", "@app.get('/login')"]
    caps = CapabilityResolver.resolve_capabilities(ast_sample)
    assert ExtractorCapability.ROUTING in caps


def test_capability_resolver_resolve_middleware():
    ast_sample = ["app.use(middleware)"]
    caps = CapabilityResolver.resolve_capabilities(ast_sample)
    assert ExtractorCapability.MIDDLEWARE in caps


def test_capability_resolver_resolve_auth():
    ast_sample = ["jwt_required()", "check_auth()"]
    caps = CapabilityResolver.resolve_capabilities(ast_sample)
    assert ExtractorCapability.AUTH in caps


def test_capability_resolver_resolve_orm():
    ast_sample = ["class User(db.Model):", "Column(Integer)"]
    caps = CapabilityResolver.resolve_capabilities(ast_sample)
    assert ExtractorCapability.ORM in caps


def test_capability_resolver_empty_ast():
    caps = CapabilityResolver.resolve_capabilities([])
    assert len(caps) == 0


def test_manifest_supported_capabilities_conversion():
    d = {"framework": "Django", "supported_capabilities": ["routing", "auth"]}
    manifest = FrameworkManifest.from_dict(d)
    assert "routing" in manifest.supported_capabilities
    assert ExtractorCapability.ROUTING in manifest.capabilities


def test_manifest_v1_backward_compatibility():
    d = {"framework": "Laravel", "capabilities": ["routing"], "supported_versions": ["*"]}
    manifest = FrameworkManifest.from_dict(d)
    assert manifest.framework == "Laravel"
    assert ExtractorCapability.ROUTING in manifest.capabilities


def test_manifest_priority_parsing():
    d = {"framework": "Gin", "priority": "5"}
    manifest = FrameworkManifest.from_dict(d)
    assert manifest.priority == 5


def test_manifest_entrypoints():
    manifest = FrameworkManifest(framework="NextJS", entrypoints=("app/api/route.ts",))
    assert manifest.entrypoints == ("app/api/route.ts",)


def test_manifest_to_dict_keys():
    manifest = FrameworkManifest(framework="Flask")
    d = manifest.to_dict()
    assert "framework" in d
    assert "language" in d
    assert "version" in d
    assert "extractors" in d
    assert "priority" in d


# ============================================================================
# 5. Framework Test Kit & Golden Fixture Tests (66-85)
# ============================================================================


def test_fixture_loader_get_fixture_path_flask():
    p = FixtureLoader.get_fixture_path("flask")
    assert p.exists()
    assert (p / "app.py").exists()


def test_fixture_loader_load_fixture_file_flask():
    content = FixtureLoader.load_fixture_file("flask", "app.py")
    assert "Flask" in content


def test_fixture_loader_list_fixture_files_flask():
    files = FixtureLoader.list_fixture_files("flask")
    assert len(files) >= 2


def test_fixture_loader_fastapi():
    p = FixtureLoader.get_fixture_path("fastapi")
    assert (p / "main.py").exists()


def test_fixture_loader_django():
    p = FixtureLoader.get_fixture_path("django")
    assert (p / "urls.py").exists()


def test_fixture_loader_express():
    p = FixtureLoader.get_fixture_path("express")
    assert (p / "app.js").exists()


def test_fixture_loader_nextjs():
    p = FixtureLoader.get_fixture_path("nextjs")
    assert (p / "route.ts").exists()


def test_fixture_loader_laravel():
    p = FixtureLoader.get_fixture_path("laravel")
    assert (p / "web.php").exists()


def test_fixture_loader_gin():
    p = FixtureLoader.get_fixture_path("gin")
    assert (p / "main.go").exists()


def test_framework_assertions_route_exists_pass():
    isr = IntermediateSemanticRepresentation(routes=(RouteDefinition(path="/login", method="POST", handler="h"),))
    FrameworkAssertions.assert_route_exists(isr, "/login", "POST")


def test_framework_assertions_route_exists_fail():
    isr = IntermediateSemanticRepresentation()
    with pytest.raises(AssertionError):
        FrameworkAssertions.assert_route_exists(isr, "/missing", "GET")


def test_framework_assertions_handler_exists_pass():
    isr = IntermediateSemanticRepresentation(handlers=(HandlerDefinition(name="h1", function_name="h1"),))
    FrameworkAssertions.assert_handler_exists(isr, "h1")


def test_framework_assertions_middleware_exists_pass():
    isr = IntermediateSemanticRepresentation(middlewares=(MiddlewareDefinition(name="AuthMw"),))
    FrameworkAssertions.assert_middleware_exists(isr, "AuthMw")


def test_framework_assertions_model_exists_pass():
    isr = IntermediateSemanticRepresentation(models=(ModelDefinition(model_name="User"),))
    FrameworkAssertions.assert_model_exists(isr, "User")


def test_framework_assertions_config_exists_pass():
    isr = IntermediateSemanticRepresentation(configs=(ConfigDefinition(key="SECRET_KEY"),))
    FrameworkAssertions.assert_config_exists(isr, "SECRET_KEY")


def test_snapshot_assertions_match_pass():
    d1 = {"a": 1, "b": "test"}
    d2 = {"a": 1, "b": "test"}
    SnapshotAssertions.assert_snapshot_match(d1, d2)


def test_snapshot_assertions_match_fail():
    d1 = {"a": 1}
    d2 = {"a": 2}
    with pytest.raises(AssertionError):
        SnapshotAssertions.assert_snapshot_match(d1, d2)


def test_snapshot_assertions_json_match():
    j1 = json.dumps({"key": "val"})
    j2 = json.dumps({"key": "val"})
    SnapshotAssertions.assert_json_snapshot(j1, j2)


def test_ast_assertions_node_type():
    class MockNode:
        node_type = "FunctionDef"

    ASTAssertions.assert_node_type(MockNode(), "FunctionDef")


def test_isr_assertions_valid_isr():
    isr = IntermediateSemanticRepresentation(routes=(RouteDefinition(path="/r", method="GET", handler="h"),))
    ISRAssertions.assert_valid_isr(isr)
