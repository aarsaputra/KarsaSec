"""Sandboxed Build Check Interface (Task Z-3 Interface Stub).

Defines interface for external sandboxed build verification (e.g. go build, php -l).
Execution is isolated from applier.py to maintain H6 security boundary.
"""

from __future__ import annotations

from pathlib import Path


class SandboxedBuildChecker:
    """Stub interface for sandboxed containerized/subprocess build verification."""

    @classmethod
    def check_build(cls, source_code: str, file_path: str | Path) -> tuple[bool | None, str | None]:
        """Performs sandboxed build check if environment permits.

        Returns:
            tuple[bool | None, str | None]: (build_success, output_log)
        """
        # Interface stub for sandboxed build checks (Task Z-3)
        return None, "Sandboxed build checker interface stub (build verification skipped)"
