"""Sprint F10 Phase 5 — F9 Security Baseline Immutability Contract Test Suite (INV-F10-AUDIT-14)."""

import subprocess
from pathlib import Path


def test_f9_protected_files_are_unmodified():
    """INV-F10-AUDIT-14: Git diff check to guarantee ZERO modifications to frozen F9 files."""
    repo_root = Path(__file__).resolve().parents[2]

    protected_paths = [
        "karsasec/recovery",
        "karsasec/events/audit_ledger.py",
        "karsasec/events/outbox.py",
    ]

    res = subprocess.run(
        ["git", "diff", "HEAD", "--"] + protected_paths,
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )

    diff_output = res.stdout.strip()
    assert len(diff_output) == 0, (
        f"F9 protected baseline violation! Changes detected in protected files:\n{diff_output}"
    )


def test_f9_recovery_suite_passes():
    """Runs tests/recovery to confirm F9 recovery engine passes with zero regressions."""
    repo_root = Path(__file__).resolve().parents[2]
    res = subprocess.run(
        ["pytest", "tests/recovery", "-q"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0, f"F9 recovery test suite failed!\nStdout:\n{res.stdout}\nStderr:\n{res.stderr}"
