"""Unit tests for multi-language rule scanning (Python, JavaScript, Go, PHP)."""

import tempfile
from pathlib import Path
from karsasec.parser.generic_parser import go_parser, php_parser
from karsasec.parser.ast import VisitorContext
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
