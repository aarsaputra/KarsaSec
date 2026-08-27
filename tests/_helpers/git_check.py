"""Centralized helper for Git Repository checks across test suites."""

from pathlib import Path
import pytest


def require_git_repo_or_skip(repo_root: Path) -> None:
    """Skips pytest execution if target repo_root is not a valid Git repository."""
    git_dir = repo_root / ".git"
    if not git_dir.exists():
        pytest.skip("Not a git repository (e.g. extracted zip archive)")
