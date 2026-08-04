"""Comprehensive unit and integration test suite for RuleExecutor, RuleIndexer, EvidenceCollector, and FindingFactory."""

import pytest
from pathlib import Path

from karsasec.core.execution import EvidenceUnavailableError, ExecutionResult, RuleExecutor, RuleIndexer, ScanContext
from karsasec.core.finding import Evidence, EvidenceCollector, Finding, FindingFactory
from karsasec.parser.ast_nodes import ASTNode, FileNode, Position
from karsasec.rules.enums import Confidence, LanguageEnum, Severity
from karsasec.rules.matcher import rule_compiler
from karsasec.rules.schema import Rule, RuleCondition, RuleMatch, RuleMetadata, RuleOutput

def create_sample_rule(
    rule_id: str = "KS-PY-0001",
    pattern: str = r"eval\(.*\)",
    node_type: str = "call_expression",
) -> Rule:
    return Rule(
        id=rule_id,
        metadata=RuleMetadata(name="Insecure Eval Usage", author="KarsaSec", version="1.0", enabled=True),
        match=RuleMatch(language=LanguageEnum.PYTHON, ast_node_types=[node_type]),
        condition=RuleCondition(pattern=pattern),
        output=RuleOutput(
            severity=Severity.CRITICAL,
            confidence="HIGH",
            message="Use of eval() detected",
            remediation="Avoid eval()",
        ),
    )

def test_rule_indexer_filtering() -> None:
    rule1 = create_sample_rule("R1", node_type="call_expression")
    rule2 = create_sample_rule("R2", node_type="import_statement")
    rule3 = create_sample_rule("R3", node_type="*")

    indexer = RuleIndexer([rule1, rule2, rule3])

    candidates = indexer.get_candidate_rules("call_expression")
    rule_ids = [c.id for c in candidates]

    assert "R1" in rule_ids
    assert "R3" in rule_ids
    assert "R2" not in rule_ids  # O(1) filtering excluded R2

def test_evidence_collector_snippet_and_context() -> None:
    source = b"import os\n# line 2\neval(user_input)\n# line 4"
    node = ASTNode(
        node_id="n1",
        node_type="call_expression",
        byte_start=19,
        byte_end=35,
        start=Position(line=3, column=0),
        end=Position(line=3, column=16),
    )

    collector = EvidenceCollector()
    evidence = collector.extract_evidence(node, source, context_window=1)

    assert evidence.snippet == "eval(user_input)"
    assert evidence.line == 3
    assert len(evidence.context_lines) > 0

def test_evidence_collector_missing_source_bytes_raises() -> None:
    node = ASTNode(node_id="n1", node_type="call_expression")
    collector = EvidenceCollector()

    with pytest.raises(EvidenceUnavailableError):
        collector.extract_evidence(node, source_bytes=None)

def test_finding_factory_fingerprint_deduplication() -> None:
    factory = FindingFactory()
    fp1 = factory.compute_fingerprint("KS-PY-0001", Path("app.py"), line=10, snippet="eval(cmd)")
    fp2 = factory.compute_fingerprint("KS-PY-0001", Path("app.py"), line=10, snippet="eval(cmd)")
    fp3 = factory.compute_fingerprint("KS-PY-0001", Path("app.py"), line=12, snippet="eval(cmd)")

    assert fp1 == fp2  # Identical findings share fingerprint
    assert fp1 != fp3  # Different line produces different fingerprint

def test_rule_executor_single_match() -> None:
    source = b"eval(user_input)"
    call_node = ASTNode(
        node_id="n1",
        node_type="call_expression",
        byte_start=0,
        byte_end=len(source),
        start=Position(line=1, column=0),
    )
    root = FileNode(node_id="r1", language="Python", children=["n1"], file_path=Path("main.py"))
    root.nodes_map = {"r1": root, "n1": call_node}

    scan_ctx = ScanContext(file_node=root, source_bytes=source, language="python", file_path=Path("main.py"))
    rule = create_sample_rule()

    executor = RuleExecutor()
    result = executor.execute_scan(scan_ctx, [rule])

    assert isinstance(result, ExecutionResult)
    assert result.files_scanned == 1
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "KS-PY-0001"
    assert finding.severity == Severity.CRITICAL
    assert finding.evidence.snippet == "eval(user_input)"

def test_rule_executor_duplicate_findings_deduplicated() -> None:
    source = b"eval(user_input)"
    call_node = ASTNode(
        node_id="n1",
        node_type="call_expression",
        byte_start=0,
        byte_end=len(source),
        start=Position(line=1, column=0),
    )
    root = FileNode(node_id="r1", language="Python", children=["n1"], file_path=Path("main.py"))
    root.nodes_map = {"r1": root, "n1": call_node}

    scan_ctx = ScanContext(file_node=root, source_bytes=source, language="python", file_path=Path("main.py"))
    rule1 = create_sample_rule("R1")
    rule2 = create_sample_rule("R1")  # Identical rule ID & match

    executor = RuleExecutor()
    result = executor.execute_scan(scan_ctx, [rule1, rule2])

    assert len(result.findings) == 1  # Deduplicated by fingerprint

def test_rule_executor_resilience_error_boundary() -> None:
    source = b"print('hello')"
    root = FileNode(node_id="r1", language="Python", children=[])
    root.nodes_map = {"r1": root}

    scan_ctx = ScanContext(file_node=root, source_bytes=source, language="python")

    executor = RuleExecutor()
    result = executor.execute_scan(scan_ctx, rules=[])

    assert result.files_scanned == 1
    assert len(result.findings) == 0
    assert len(result.errors) == 0
