"""Unit tests for multi-language rule scanning (Python, JavaScript, Go, PHP)."""

import tempfile
from pathlib import Path
from unittest.mock import patch

from karsasec.core.execution import RuleExecutor, ScanContext
from karsasec.parser.ast import VisitorContext
from karsasec.parser.generic_parser import go_parser, js_parser, php_parser
from karsasec.parser.python_parser import PythonParserPlugin
from karsasec.parser.tree_sitter import ts_engine
from karsasec.rules.loader import YAMLRuleLoader
from karsasec.rules.matcher import ASTMatcher, rule_compiler


def test_go_ssrf_rule_matching() -> None:
    """Verify Go SSRF rule triggers on unsafe http.Get calls."""
    go_code = """
package main

import (
    "net/http"
    "fmt"
)

func fetch_url(req_url string) {
    resp, err := http.Get(req_url)
    if err != nil {
        fmt.Println(err)
    }
}
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        file_path = Path(tmpdir) / "main.go"
        file_path.write_text(go_code)

        parse_result = go_parser.parse_file(file_path)
        # Ensure root node has correct language set
        parse_result.root.language = "Go"

        loader = YAMLRuleLoader()
        rules = loader.load_directory(Path("karsasec/rules/patterns/go"))

        matcher = ASTMatcher()
        context = VisitorContext(file_node=parse_result.root, language="Go")
        matched = False

        for node_id, node in parse_result.root.nodes_map.items():
            node.language = "Go"
            for rule in rules:
                compiled = rule_compiler.compile(rule)
                res = matcher.match(node, compiled, context, source_bytes=go_code.encode("utf-8"))
                if res.matched:
                    matched = True
                    break

        assert matched is True, "Expected Go SSRF rule to trigger on http.Get call"


def test_php_path_traversal_rule_matching() -> None:
    """Verify PHP Path Traversal rule triggers on unsafe include with $_GET."""
    php_code = """<?php
$page = $_GET['page'];
include($page);
?>"""
    with tempfile.TemporaryDirectory() as tmpdir:
        file_path = Path(tmpdir) / "index.php"
        file_path.write_text(php_code)

        parse_result = php_parser.parse_file(file_path)
        parse_result.root.language = "PHP"

        loader = YAMLRuleLoader()
        rules = loader.load_directory(Path("karsasec/rules/patterns/php"))

        matcher = ASTMatcher()
        context = VisitorContext(file_node=parse_result.root, language="PHP")
        matched = False

        for node_id, node in parse_result.root.nodes_map.items():
            node.language = "PHP"
            for rule in rules:
                compiled = rule_compiler.compile(rule)
                res = matcher.match(node, compiled, context, source_bytes=php_code.encode("utf-8"))
                if res.matched:
                    matched = True
                    break

        assert matched is True, "Expected PHP Path Traversal rule to trigger on include($_GET)"


def test_php_sqli_rule_ignores_comment_only_query_in_fallback(tmp_path: Path) -> None:
    """Verify PHP SQL Injection rule does not match query text inside comments in the fallback parser."""
    php_code = """<?php
/*
|--------------------------------------------------------------------------
| Here you may specify which of the database connections below you wish
| to use as your default connection for database operations. This is
| is explicitly specified when you execute a query / statement.
|--------------------------------------------------------------------------
*/
return [
    'default' => [
        'driver' => 'mysql',
        'host' => env('DB_HOST', '127.0.0.1'),
    ],
];
"""
    file_path = tmp_path / "database.php"
    file_path.write_text(php_code, encoding="utf-8")

    with patch.object(ts_engine, "get_language", return_value=None):
        parse_result = php_parser.parse_file(file_path)

    parse_result.root.language = "PHP"

    loader = YAMLRuleLoader()
    rules = loader.load_directory(Path("karsasec/rules/patterns/php"))
    sqli_rules = [rule for rule in rules if rule.id == "KS-PHP-0002"]

    executor = RuleExecutor()
    scan_ctx = ScanContext(
        file_node=parse_result.root,
        source_bytes=php_code.encode("utf-8"),
        file_path=file_path,
        symbol_table=parse_result.symbol_table,
        language="PHP",
    )
    result = executor.execute_scan(scan_ctx, sqli_rules)

    assert len(result.findings) == 0, "Expected no SQL Injection findings for comment-only query text"


def test_php_rce_rule_does_not_trigger_on_logger_function_name(tmp_path: Path) -> None:
    """Verify PHP RCE rule does not false-positive on names like system_error."""
    php_code = """<?php
function report_error($id, $current_user_id, $e) {
    logSecurityEvent('system_error', $id, $current_user_id, $e->getMessage());
}
"""
    file_path = tmp_path / "impossible.php"
    file_path.write_text(php_code, encoding="utf-8")

    with patch.object(ts_engine, "get_language", return_value=None):
        parse_result = php_parser.parse_file(file_path)

    parse_result.root.language = "PHP"

    loader = YAMLRuleLoader()
    rules = loader.load_directory(Path("karsasec/rules/patterns/php"))
    rce_rules = [rule for rule in rules if rule.id == "KS-PHP-0001"]

    executor = RuleExecutor()
    scan_ctx = ScanContext(
        file_node=parse_result.root,
        source_bytes=php_code.encode("utf-8"),
        file_path=file_path,
        symbol_table=parse_result.symbol_table,
        language="PHP",
    )
    result = executor.execute_scan(scan_ctx, rce_rules)

    assert len(result.findings) == 0, "Expected no RCE findings for function name containing system_error"


def test_php_sqli_rule_ignores_static_mysqli_query_without_user_input(tmp_path: Path) -> None:
    """Verify PHP SQL Injection rule ignores benign mysqli_query calls without tainted input."""
    php_code = """<?php
$result = mysqli_query($GLOBALS['___mysqli_ston'], "SHOW COLUMNS FROM users LIKE 'role'");
"""
    file_path = tmp_path / "safe_query.php"
    file_path.write_text(php_code, encoding="utf-8")

    with patch.object(ts_engine, "get_language", return_value=None):
        parse_result = php_parser.parse_file(file_path)

    parse_result.root.language = "PHP"

    loader = YAMLRuleLoader()
    rules = loader.load_directory(Path("karsasec/rules/patterns/php"))
    sqli_rules = [rule for rule in rules if rule.id == "KS-PHP-0002"]

    executor = RuleExecutor()
    scan_ctx = ScanContext(
        file_node=parse_result.root,
        source_bytes=php_code.encode("utf-8"),
        file_path=file_path,
        symbol_table=parse_result.symbol_table,
        language="PHP",
    )
    result = executor.execute_scan(scan_ctx, sqli_rules)

    assert len(result.findings) == 0, "Expected no SQL Injection findings for benign static mysqli_query"


def test_php_sqli_rule_detects_tainted_variable_flow(tmp_path: Path) -> None:
    """Verify PHP SQL Injection rule detects taint when a variable comes from $_GET."""
    php_code = """<?php
$id = $_GET['user_id'];
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id'";
$result = mysqli_query($GLOBALS['___mysqli_ston'], $query);
"""
    file_path = tmp_path / "tainted_flow.php"
    file_path.write_text(php_code, encoding="utf-8")

    with patch.object(ts_engine, "get_language", return_value=None):
        parse_result = php_parser.parse_file(file_path)

    parse_result.root.language = "PHP"

    loader = YAMLRuleLoader()
    rules = loader.load_directory(Path("karsasec/rules/patterns/php"))
    sqli_rules = [rule for rule in rules if rule.id == "KS-PHP-0002"]

    executor = RuleExecutor()
    scan_ctx = ScanContext(
        file_node=parse_result.root,
        source_bytes=php_code.encode("utf-8"),
        file_path=file_path,
        symbol_table=parse_result.symbol_table,
        language="PHP",
    )
    result = executor.execute_scan(scan_ctx, sqli_rules)

    assert len(result.findings) == 1, "Expected SQL Injection finding when variable is tainted from $_GET"


def test_php_bac_rule_detects_request_controlled_access_decision(tmp_path: Path) -> None:
    """Verify PHP Broken Access Control rule detects auth decisions based on request-controlled IDs."""
    php_code = """<?php
if (isset($_GET['action']) && isset($_GET['user_id']) && isset($_COOKIE['user_id'])) {
    $id = intval($_GET['user_id']);
    if ($id == intval($_COOKIE['user_id'])) {
        $query = "SELECT first_name, last_name FROM users WHERE user_id = $id;";
        mysqli_query($GLOBALS['___mysqli_ston'], $query);
    }
}
"""
    file_path = tmp_path / "bac_flow.php"
    file_path.write_text(php_code, encoding="utf-8")

    with patch.object(ts_engine, "get_language", return_value=None):
        parse_result = php_parser.parse_file(file_path)

    parse_result.root.language = "PHP"

    loader = YAMLRuleLoader()
    rules = loader.load_directory(Path("karsasec/rules/patterns/php"))
    bac_rules = [rule for rule in rules if rule.id == "KS-PHP-0008"]

    executor = RuleExecutor()
    scan_ctx = ScanContext(
        file_node=parse_result.root,
        source_bytes=php_code.encode("utf-8"),
        file_path=file_path,
        symbol_table=parse_result.symbol_table,
        language="PHP",
    )
    result = executor.execute_scan(scan_ctx, bac_rules)

    assert len(result.findings) >= 1, (
        "Expected at least one Broken Access Control finding when user-controlled IDs determine access"
    )


def test_python_weak_crypto_rule_detects_md5() -> None:
    python_code = """import hashlib
password = 'secret'
hash_result = hashlib.md5(password.encode('utf-8')).hexdigest()
print(hash_result)
"""
    file_path = Path("/tmp/test_python_crypto.py")
    file_path.write_text(python_code, encoding="utf-8")

    parse_result = PythonParserPlugin().parse_file(file_path)
    parse_result.root.language = "Python"

    loader = YAMLRuleLoader()
    rules = loader.load_directory(Path("karsasec/rules/patterns/python"))
    crypto_rules = [rule for rule in rules if rule.id == "KS-PY-0004"]

    executor = RuleExecutor()
    scan_ctx = ScanContext(
        file_node=parse_result.root,
        source_bytes=python_code.encode("utf-8"),
        file_path=file_path,
        symbol_table=parse_result.symbol_table,
        language="Python",
    )
    result = executor.execute_scan(scan_ctx, crypto_rules)

    assert len(result.findings) >= 1, "Expected weak crypto finding for hashlib.md5 usage"


def test_javascript_cors_misconfig_rule_detects_wildcard_origin(tmp_path: Path) -> None:
    js_code = """const express = require('express');
const cors = require('cors');
const app = express();
app.use(cors());
"""
    file_path = tmp_path / "test_cors_misconfig.js"
    file_path.write_text(js_code, encoding="utf-8")

    with patch.object(ts_engine, "get_language", return_value=None):
        parse_result = js_parser.parse_file(file_path)

    parse_result.root.language = "JavaScript"

    loader = YAMLRuleLoader()
    rules = loader.load_directory(Path("karsasec/rules/patterns/javascript"))
    cors_rules = [rule for rule in rules if rule.id == "KS-JS-0006"]

    executor = RuleExecutor()
    scan_ctx = ScanContext(
        file_node=parse_result.root,
        source_bytes=js_code.encode("utf-8"),
        file_path=file_path,
        symbol_table=parse_result.symbol_table,
        language="JavaScript",
    )
    result = executor.execute_scan(scan_ctx, cors_rules)

    assert len(result.findings) >= 1, "Expected CORS misconfiguration finding on cors() wildcard usage"


def test_go_deserialization_rule_detects_gob_decoder(tmp_path: Path) -> None:
    go_code = """package main

import (
    \"encoding/gob\"
    \"net/http\"
)

type Payload struct {
    Name string
}

func handler(w http.ResponseWriter, r *http.Request) {
    var payload Payload
    decoder := gob.NewDecoder(r.Body)
    _ = decoder.Decode(&payload)
    w.Write([]byte(payload.Name))
}
"""
    file_path = tmp_path / "test_deserialize.go"
    file_path.write_text(go_code, encoding="utf-8")

    with patch.object(ts_engine, "get_language", return_value=None):
        parse_result = go_parser.parse_file(file_path)

    parse_result.root.language = "Go"

    loader = YAMLRuleLoader()
    rules = loader.load_directory(Path("karsasec/rules/patterns/go"))
    deser_rules = [rule for rule in rules if rule.id == "KS-GO-0008"]

    executor = RuleExecutor()
    scan_ctx = ScanContext(
        file_node=parse_result.root,
        source_bytes=go_code.encode("utf-8"),
        file_path=file_path,
        symbol_table=parse_result.symbol_table,
        language="Go",
    )
    result = executor.execute_scan(scan_ctx, deser_rules)

    assert len(result.findings) >= 1, "Expected unsafe deserialization finding for gob.NewDecoder usage"
