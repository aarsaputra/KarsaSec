"""Snapshot and Regression Test Suite for Enterprise TargetDetector, ParsedDocument, and SARIF Output."""

from pathlib import Path

from karsasec.parser.target_detector import TargetDetector, target_detector
from karsasec.rules.enums import TargetFormatEnum, TargetKindEnum
from karsasec.iac.scanner import IaCScanner
from karsasec.core.reporting.sarif_reporter import SARIFReporter
from karsasec.core.reporting.target import StringTarget
from karsasec.core.execution.result import ExecutionResult


def test_target_detector_heuristics() -> None:
    """Verify TargetDetector correctly classifies Dockerfile, K8s, GitHub Actions, and Terraform."""
    detector = TargetDetector()

    res1 = detector.detect(Path("/repo/Dockerfile"))
    assert res1.target_kind == TargetKindEnum.IAC
    assert res1.target_format == TargetFormatEnum.DOCKERFILE

    res2 = detector.detect(Path("/repo/.github/workflows/deploy.yml"), content="on:\n  push:\njobs:")
    assert res2.target_kind == TargetKindEnum.PIPELINE
    assert res2.target_format == TargetFormatEnum.GITHUB_ACTIONS

    res3 = detector.detect(Path("/repo/k8s/pod.yaml"), content="apiVersion: v1\nkind: Pod")
    assert res3.target_kind == TargetKindEnum.MANIFEST
    assert res3.target_format == TargetFormatEnum.KUBERNETES

    res4 = detector.detect(Path("/repo/main.tf"))
    assert res4.target_kind == TargetKindEnum.IAC
    assert res4.target_format == TargetFormatEnum.TERRAFORM


def test_golden_corpus_regression_scan() -> None:
    """Verify scanner execution against tests/golden/ benchmark suite."""
    scanner = IaCScanner()

    # Golden Dockerfile
    docker_findings = scanner.scan_file(Path("tests/golden/Dockerfile"))
    docker_rule_ids = {f.rule_id for f in docker_findings}
    assert "KS-DOCKER-0001" in docker_rule_ids  # Root user
    assert "KS-DOCKER-0002" in docker_rule_ids  # Unpinned tag
    assert "KS-DOCKER-0004" in docker_rule_ids  # curl | sh
    assert "KS-DOCKER-0005" in docker_rule_ids  # Secret ENV

    # Golden Kubernetes Deployment
    k8s_findings = scanner.scan_file(Path("tests/golden/deployment.yaml"))
    k8s_rule_ids = {f.rule_id for f in k8s_findings}
    assert "KS-K8S-0001" in k8s_rule_ids  # Privileged
    assert "KS-K8S-0003" in k8s_rule_ids  # hostNetwork
    assert "KS-K8S-0004" in k8s_rule_ids  # runAsNonRoot: false

    # Golden GitHub Actions Workflow
    gha_findings = scanner.scan_file(Path("tests/golden/ci.yml"))
    gha_rule_ids = {f.rule_id for f in gha_findings}
    assert "KS-GHA-0001" in gha_rule_ids  # Script injection
    assert "KS-GHA-0002" in gha_rule_ids  # pull_request_target


def test_sarif_snapshot_generation() -> None:
    """Verify SARIF output generation for IaC findings."""
    scanner = IaCScanner()
    findings = scanner.scan_file(Path("tests/golden/Dockerfile"))
    assert len(findings) >= 3

    exec_result = ExecutionResult(
        scan_id="scan-123",
        timestamp="2026-08-05T00:00:00Z",
        files_scanned=1,
        rules_checked=5,
        nodes_processed=10,
        findings=tuple(findings),
    )
    target = StringTarget()

    reporter = SARIFReporter()
    reporter.generate(exec_result, target)

    output = target.get_content()
    assert '"version": "2.1.0"' in output
    assert '"name": "KarsaSec"' in output
    assert "KS-DOCKER-0001" in output
