"""Unit tests for Phase 5 Auth, Middleware, and Config Extractors."""

from dataclasses import dataclass, field
from typing import Any

from karsasec.framework.extractors.auth_extractor import AuthSemanticExtractor
from karsasec.framework.extractors.base import ExtractorContext
from karsasec.framework.extractors.config_extractor import ConfigurationSemanticExtractor
from karsasec.framework.extractors.middleware_extractor import MiddlewareSemanticExtractor
from karsasec.framework.semantic_fact import SemanticRole


@dataclass
class MockASTNode:
    node_type: str
    name: str
    id: str = "memory_node"
    file_path: str = "app.py"
    line_number: int = 1
    attributes: dict[str, Any] = field(default_factory=dict)


def test_auth_extractor_flask() -> None:
    """AuthSemanticExtractor extracts login_required decorator."""
    ext = AuthSemanticExtractor()
    nodes = [
        MockASTNode("DECORATOR", "@login_required", id="n1", line_number=5)
    ]
    ctx = ExtractorContext(framework="FLASK", ast_nodes=nodes)
    res = ext.extract(ctx)

    assert len(res.statistics) == 1
    fact_dict = list(res.statistics.values())[0]
    assert fact_dict["kind"] == "auth"
    assert fact_dict["semantic_role"] == SemanticRole.AUTHENTICATION_CHECK.value


def test_middleware_extractor_express() -> None:
    """MiddlewareSemanticExtractor extracts Express middleware registration."""
    ext = MiddlewareSemanticExtractor()
    nodes = [
        MockASTNode("CALL", "app.use(cors())", id="n2", line_number=10)
    ]
    ctx = ExtractorContext(framework="EXPRESS", ast_nodes=nodes)
    res = ext.extract(ctx)

    assert len(res.statistics) == 1
    fact_dict = list(res.statistics.values())[0]
    assert fact_dict["kind"] == "middleware"
    assert fact_dict["semantic_role"] == SemanticRole.MIDDLEWARE.value
    assert fact_dict["metadata"]["execution_order"] == 1


def test_config_extractor_django() -> None:
    """ConfigurationSemanticExtractor extracts Django ALLOWED_HOSTS config."""
    ext = ConfigurationSemanticExtractor()
    nodes = [
        MockASTNode("ASSIGN", "ALLOWED_HOSTS = ['*']", id="n3", line_number=20)
    ]
    ctx = ExtractorContext(framework="DJANGO", ast_nodes=nodes)
    res = ext.extract(ctx)

    assert len(res.statistics) == 1
    fact_dict = list(res.statistics.values())[0]
    assert fact_dict["kind"] == "config"
    assert fact_dict["semantic_role"] == SemanticRole.SECURITY_CONFIGURATION.value
    assert fact_dict["metadata"]["config_type"] == "trusted_hosts"
