"""Unit test suite for Infrastructure as Code (IaC) Scanner delegating to Rule Engine v2."""

import tempfile
from pathlib import Path

from karsasec.iac.scanner import IaCScanner


def test_scan_dockerfile_misconfigurations() -> None:
    """Verify Dockerfile scan detects missing non-root USER, unpinned latest tag, and curl | sh."""
    dockerfile_content = """FROM ubuntu:latest
USER root
RUN curl http://example.com/script.sh | sh
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        dfile = Path(tmpdir) / "Dockerfile"
        dfile.write_text(dockerfile_content)

        scanner = IaCScanner()
        findings = scanner.scan_file(dfile)

        rule_ids = [f.rule_id for f in findings]

        # Should detect root user (KS-DOCKER-0001), unpinned tag (KS-DOCKER-0002), curl | sh (KS-DOCKER-0004)
        assert "KS-DOCKER-0001" in rule_ids
        assert "KS-DOCKER-0002" in rule_ids
        assert "KS-DOCKER-0004" in rule_ids


def test_scan_kubernetes_privileged_container() -> None:
    """Verify Kubernetes YAML scan detects privileged: true."""
    k8s_content = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnerable-app
spec:
  template:
    spec:
      containers:
      - name: web
        image: nginx:1.21
        securityContext:
          privileged: true
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        kfile = Path(tmpdir) / "deployment.yaml"
        kfile.write_text(k8s_content)

        scanner = IaCScanner()
        findings = scanner.scan_file(kfile)

        rule_ids = [f.rule_id for f in findings]
        assert "KS-K8S-0001" in rule_ids  # Privileged container


def test_scan_github_actions_script_injection() -> None:
    """Verify GitHub Actions workflow scan detects unescaped github.event context in run script."""
    workflow_content = """name: CI
on:
  pull_request_target:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Title: ${{ github.event.issue.title }}"
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        wfile = Path(tmpdir) / ".github" / "workflows" / "ci.yml"
        wfile.parent.mkdir(parents=True, exist_ok=True)
        wfile.write_text(workflow_content)

        scanner = IaCScanner()
        findings = scanner.scan_file(wfile)

        rule_ids = [f.rule_id for f in findings]
        assert "KS-GHA-0001" in rule_ids  # Inline script injection
        assert "KS-GHA-0002" in rule_ids  # Dangerous pull_request_target
