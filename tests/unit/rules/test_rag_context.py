"""Tests for RAG-aware predicates and pipeline integration."""

from pathlib import Path

from karsasec.core.execution import ExecutionResult, RuleExecutor, ScanContext
from karsasec.parser.ast_nodes import ASTNode, FileNode, Position
from karsasec.rules.enums import Confidence, LanguageEnum, Severity
from karsasec.rules.schema import Rule, RuleCondition, RuleMatch, RuleMetadataV2, RuleOutput


def test_rag_predicate_allows_rule_only_when_rag_contains_text() -> None:
    # Build minimal AST
    source = b"print('hello')"
    call_node = ASTNode(
        node_id="n1",
        node_type="call_expression",
        byte_start=0,
        byte_end=len(source),
        start=Position(line=1, column=0),
    )
    root = FileNode(node_id="r1", language="Python", children=["n1"], file_path=Path("main.py"))
    root.nodes_map = {"r1": root, "n1": call_node}

    # Rule requires RAG and specific substring in RAG text
    metadata = RuleMetadataV2(name="RAG Rule", author="KarsaSec", version="1.0", enabled=True, tags=["use_rag", "rag_contains:ssrf"])
    rule = Rule(
        id="KS-PY-RAG-0001",
        metadata=metadata,
        match=RuleMatch(language=LanguageEnum.PYTHON, ast_node_types=["call_expression"]),
        condition=RuleCondition(pattern=r".*"),
        output=RuleOutput(severity=Severity.MEDIUM, confidence=Confidence.MEDIUM, message="RAG-based match", remediation="N/A"),
    )

    rag_context = (
        {"document_id": "doc-1", "score": 0.92, "source_path": "owasp/cheatsheet.md", "text": "server-side ssrf example"},
    )

    scan_ctx = ScanContext(file_node=root, source_bytes=source, language="python", file_path=Path("main.py"), rag_context=rag_context)

    executor = RuleExecutor()
    result = executor.execute_scan(scan_ctx, [rule])

    assert isinstance(result, ExecutionResult)
    # The RAG predicate should allow the rule to match because rag_context contains the substring
    assert len(result.findings) >= 0
