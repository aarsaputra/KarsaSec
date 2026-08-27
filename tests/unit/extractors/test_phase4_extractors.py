"""Unit tests for Phase 4 Endpoint, Input, and Sink Extractors."""

from dataclasses import dataclass, field
from typing import Any

from karsasec.framework.extractors.base import ExtractorContext
from karsasec.framework.extractors.endpoint_extractor import HTTPEndpointExtractor
from karsasec.framework.extractors.input_extractor import HTTPInputSourceExtractor
from karsasec.framework.extractors.sink_extractor import SecuritySinkExtractor
from karsasec.framework.semantic_fact import SemanticRole


@dataclass
class MockASTNode:
    node_type: str
    name: str
    id: str = "memory_node"
    file_path: str = "app.py"
    line_number: int = 1
    attributes: dict[str, Any] = field(default_factory=dict)



def test_endpoint_extractor_flask() -> None:
    """HTTPEndpointExtractor extracts Flask endpoint fact correctly."""
    ext = HTTPEndpointExtractor()
    nodes = [
        MockASTNode("DECORATOR", "@app.route('/api/users', methods=['GET'])", id="n1", line_number=10)
    ]
    ctx = ExtractorContext(framework="FLASK", ast_nodes=nodes)
    res = ext.extract(ctx)

    assert len(res.statistics) == 1
    fact_dict = list(res.statistics.values())[0]
    assert fact_dict["kind"] == "endpoint"
    assert fact_dict["semantic_role"] == SemanticRole.HTTP_ENDPOINT.value
    assert fact_dict["metadata"]["path"] == "/api/users"
    assert fact_dict["metadata"]["method"] == "GET"


def test_input_extractor_express() -> None:
    """HTTPInputSourceExtractor extracts Express req.query input fact."""
    ext = HTTPInputSourceExtractor()
    nodes = [
        MockASTNode("EXPRESSION", "const user = req.query.username", id="n2", line_number=15)
    ]
    ctx = ExtractorContext(framework="EXPRESS", ast_nodes=nodes)
    res = ext.extract(ctx)

    assert len(res.statistics) == 1
    fact_dict = list(res.statistics.values())[0]
    assert fact_dict["kind"] == "source"
    assert fact_dict["source_kind"] == "http_user_input"
    assert fact_dict["metadata"]["channel"] == "query_param"


def test_sink_extractor_sql() -> None:
    """SecuritySinkExtractor extracts SQL execute sink fact."""
    ext = SecuritySinkExtractor()
    nodes = [
        MockASTNode("CALL", "db.execute('SELECT * FROM users')", id="n3", line_number=25)
    ]
    ctx = ExtractorContext(framework="FLASK", ast_nodes=nodes)
    res = ext.extract(ctx)

    assert len(res.statistics) == 1
    fact_dict = list(res.statistics.values())[0]
    assert fact_dict["kind"] == "sink"
    assert fact_dict["sink_category"] == "sql"


def test_phase4_extractors_unknown_framework_guard() -> None:
    """Extractors must produce NO facts when framework is UNKNOWN (Guard 2)."""
    ep_ext = HTTPEndpointExtractor()
    inp_ext = HTTPInputSourceExtractor()
    sink_ext = SecuritySinkExtractor()

    nodes = [
        MockASTNode("DECORATOR", "@app.route('/api')"),
        MockASTNode("EXPRESSION", "req.query"),
        MockASTNode("CALL", "db.execute('query')"),
    ]
    ctx = ExtractorContext(framework="UNKNOWN", ast_nodes=nodes)

    assert len(ep_ext.extract(ctx).statistics) == 0
    assert len(inp_ext.extract(ctx).statistics) == 0
    assert len(sink_ext.extract(ctx).statistics) == 0
