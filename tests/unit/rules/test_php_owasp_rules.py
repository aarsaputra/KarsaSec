from pathlib import Path
from unittest.mock import patch

from karsasec.core.execution import RuleExecutor, ScanContext
from karsasec.parser.generic_parser import php_parser
from karsasec.parser.tree_sitter import ts_engine
from karsasec.rules.loader import YAMLRuleLoader


def _run_rule_on_code(php_code: str, rule_id: str):
    file_path = Path('/tmp/test_php_snippet.php')
    file_path.write_text(php_code, encoding='utf-8')
    with patch.object(ts_engine, 'get_language', return_value=None):
        parse_result = php_parser.parse_file(file_path)
    parse_result.root.language = 'PHP'
    loader = YAMLRuleLoader()
    rules = loader.load_directory(Path('karsasec/rules/patterns/php'))
    target = [r for r in rules if r.id == rule_id]
    executor = RuleExecutor()
    scan_ctx = ScanContext(
        file_node=parse_result.root,
        source_bytes=php_code.encode('utf-8'),
        file_path=file_path,
        symbol_table=parse_result.symbol_table,
        language='PHP',
    )
    return executor.execute_scan(scan_ctx, target)


def test_php_crypto_weak_detects_md5():
    code = """<?php
$h = md5($password);
"""
    res = _run_rule_on_code(code, 'KS-PHP-CRYPTO-0001')
    assert len(res.findings) >= 1


def test_php_misconfig_detects_ini_set():
    code = """<?php
ini_set('display_errors', '1');
"""
    res = _run_rule_on_code(code, 'KS-PHP-0009')
    assert len(res.findings) >= 1


def test_php_auth_detects_md5_usage():
    code = """<?php
$hash = md5($password);
"""
    res = _run_rule_on_code(code, 'KS-PHP-AUTH-0001')
    assert len(res.findings) >= 1


def test_php_deser_detects_unserialize(tmp_path: Path):
    code = """<?php
$data = unserialize($_POST['payload']);
"""
    res = _run_rule_on_code(code, 'KS-PHP-DESER-0001')
    assert len(res.findings) >= 1


def test_php_ssrf_detects_file_get_contents():
    code = """<?php
$url = $_GET['url'];
$file = file_get_contents($url);
"""
    res = _run_rule_on_code(code, 'KS-PHP-SSRF-0001')
    assert len(res.findings) >= 1
