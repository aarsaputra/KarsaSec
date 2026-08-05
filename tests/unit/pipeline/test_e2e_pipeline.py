"""End-to-End Multi-Language Pipeline Integration Test Suite."""

import tempfile
from pathlib import Path
from karsasec.parser.python_parser import python_parser_plugin
from karsasec.parser.generic_parser import js_parser, go_parser, php_parser
from karsasec.semantic.resolver import SemanticResolver
from karsasec.graph.builder import ProjectGraphBuilder
from karsasec.rules.loader import YAMLRuleLoader
from karsasec.rules.matcher import ASTMatcher, rule_compiler
from karsasec.parser.ast import VisitorContext


def test_e2e_multi_language_pipeline() -> None:
    """Verify that Python, JS, Go, and PHP files flow through identical pipeline layers to produce findings."""
    code_samples = {
        "Python": ("app.py", "import os\nos.system(cmd)"),
        "JavaScript": ("app.js", "eval(user_input)"),
        "Go": ("main.go", "package main\nimport \"net/http\"\nfunc f(u string) { http.Get(u) }"),
        "PHP": ("index.php", "<?php $p = $_GET['p']; include($p); ?>"),
    }

    parsers = {
        "Python": python_parser_plugin,
        "JavaScript": js_parser,
        "Go": go_parser,
        "PHP": php_parser,
    }

    rule_dirs = {
        "Python": Path("karsasec/rules/patterns/python"),
        "JavaScript": Path("karsasec/rules/patterns/javascript"),
        "Go": Path("karsasec/rules/patterns/go"),
        "PHP": Path("karsasec/rules/patterns/php"),
    }

    loader = YAMLRuleLoader()
    resolver = SemanticResolver()
    graph_builder = ProjectGraphBuilder()
    matcher = ASTMatcher()

    with tempfile.TemporaryDirectory() as tmpdir:
        for lang, (filename, code_text) in code_samples.items():
            file_path = Path(tmpdir) / filename
            file_path.write_text(code_text)

            # 1. Parsing
            parser = parsers[lang]
            parse_result = parser.parse_file(file_path)
            assert parse_result.root is not None, f"Failed parsing {lang}"

            # 2. Semantic Resolution
            sem_graph = resolver.resolve_file(parse_result.root)
            assert sem_graph is not None, f"Failed semantic graph for {lang}"

            # 3. ProjectGraph Construction
            project_graph = graph_builder.build([parse_result.root], {file_path: sem_graph})
            assert len(project_graph.nodes) > 0, f"ProjectGraph empty for {lang}"

            # 4. Rule Matching
            rules = loader.load_directory(rule_dirs[lang])
            assert len(rules) > 0, f"No rules loaded for {lang}"

            matched = False
            context = VisitorContext(
                file_node=parse_result.root,
                language=lang,
            )

            for node_id, node in parse_result.root.nodes_map.items():
                node.language = lang
                for rule in rules:
                    compiled = rule_compiler.compile(rule)
                    res = matcher.match(node, compiled, context, source_bytes=code_text.encode("utf-8"))
                    if res.matched:
                        matched = True
                        break

            assert matched is True, f"End-to-end pipeline failed to match rule for {lang}"
