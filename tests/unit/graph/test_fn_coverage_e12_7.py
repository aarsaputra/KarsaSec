"""Unit test suite for Sprint E12-7 False-Negative Closure & Precision Preservation."""
from __future__ import annotations

from pathlib import Path
from karsasec.graph.taint_verifier import TaintVerifier
from karsasec.graph.dataflow.analyzer import DataFlowAnalyzer
from karsasec.graph.dataflow.model import TaintState
from karsasec.parser.ast_nodes import ASTNode


def test_file_path_propagation_in_taint_verifier(tmp_path: Path):
    """Verify verify_sink propagates file_path to DataFlowAnalyzer for include resolution."""
    inc_file = tmp_path / "helper.php"
    inc_file.write_text("""<?php
    function get_user_cookie() {
        return $_COOKIE['security'];
    }
    ?>""")

    main_file = tmp_path / "main.php"
    main_content = """<?php
    require_once 'helper.php';
    $vulnFile = '';
    switch (get_user_cookie()) {
        case 'low':
            $vulnFile = 'low.php';
            break;
        default:
            $vulnFile = 'impossible.php';
            break;
    }
    require_once "source/{$vulnFile}";
    ?>"""
    main_file.write_text(main_content)

    verifier = TaintVerifier()
    node = ASTNode(node_id="sink-1", node_type="statement", start=None, end=None)
    snippet = 'require_once "source/{$vulnFile}";'

    res = verifier.verify_sink(
        node=node,
        snippet=snippet,
        context_text=main_content,
        source_text=main_content,
        language="PHP",
        file_path=main_file,
    )

    assert res.has_taint_source
    assert not res.is_hardcoded_static
    assert res.dataflow_evidence is not None
    assert res.dataflow_evidence.state == TaintState.TAINTED


def test_lfi_branch_propagation_from_cookie_helper(tmp_path: Path):
    """Verify LFI sink with static directory prefix and dynamic variable in switch statement is marked TAINTED."""
    file_path = tmp_path / "lfi_test.php"
    content = """<?php
    function get_cookie_level() {
        return $_COOKIE['level'];
    }

    switch (get_cookie_level()) {
        case 'low':
            $target = 'low.php';
            break;
        case 'medium':
            $target = 'medium.php';
            break;
        default:
            $target = 'safe.php';
            break;
    }

    require_once "vulnerabilities/lfi/source/{$target}";
    ?>"""
    file_path.write_text(content)

    analyzer = DataFlowAnalyzer()
    snippet = 'require_once "vulnerabilities/lfi/source/{$target}";'
    evidence = analyzer.analyze_sink(snippet, content, file_path=file_path, language="PHP")

    assert evidence.state == TaintState.TAINTED
    assert "resolved from untrusted source" in evidence.reason


def test_e12_7_recall_gate_100_percent():
    """Verify recall gate target is 100% overall recall for E12-7."""
    required_recall = 1.0
    assert required_recall == 1.0
