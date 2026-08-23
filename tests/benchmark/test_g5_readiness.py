"""G5-1 Benchmark Readiness & Reproducibility Audit Unit Tests.

Verifies:
1. BenchmarkReadinessReport generation with git commit, dirty worktree status, python version, configuration hash
2. INV-G5-ORACLE-INDEPENDENCE-01: Oracle independence verification
3. G5-1B: Benchmark determinism verification
"""

from karsasec.benchmark.readiness import BenchmarkReadinessAuditor


def test_benchmark_readiness_audit_execution() -> None:
    auditor = BenchmarkReadinessAuditor()
    report = auditor.perform_readiness_audit(dataset_name="OWASP_BENCHMARK", dataset_version="v1.2")

    assert report.is_blocked is False
    assert report.oracle_independence_verified is True
    assert report.determinism_verified is True
    assert report.engine_version == "v1.0.0"
    assert len(report.git_commit) >= 7
    assert isinstance(report.dirty_worktree.is_clean, bool)


def test_oracle_independence_verification() -> None:
    auditor = BenchmarkReadinessAuditor()
    ok, msg = auditor.verify_oracle_independence()
    assert ok is True
    assert "INV-G5-ORACLE-INDEPENDENCE-01" in msg


def test_benchmark_determinism_verification() -> None:
    auditor = BenchmarkReadinessAuditor()
    ok, msg = auditor.verify_benchmark_determinism()
    assert ok is True
    assert "G5-1B" in msg
