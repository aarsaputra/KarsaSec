"""Unit test suite for Sprint PG-1 — Program Governance & Roadmap Lock Engine.

Verifies invariants INV-PROGRAM-01 through INV-PROGRAM-05 and INV-SPEC-01 through INV-SPEC-03.
"""

import json
from pathlib import Path

from karsasec.governance.program_lock import (
    ProgramGovernanceEngine,
    ProgramLockState,
    ProgramVerdict,
    verify_program_roadmap_lock,
)


def test_pg1_01_valid_roadmap_lock_evaluates_active() -> None:
    """PG1-01 — Valid ROADMAP_LOCK.json and PROGRAM_EXECUTION_SPEC.md returns ACTIVE / IN_PROGRESS."""
    res = verify_program_roadmap_lock()
    assert res.state == ProgramLockState.ACTIVE
    assert res.verdict == ProgramVerdict.IN_PROGRESS
    assert res.is_valid is True


def test_pg1_02_exceeding_track_c_boundary_returns_blocked() -> None:
    """PG1-02 — Attempting to run Sprint F16 on Track C returns BLOCKED (INV-PROGRAM-01)."""
    res = verify_program_roadmap_lock(requested_track="C", requested_sprint="F16")
    assert res.state == ProgramLockState.BLOCKED
    assert res.verdict == ProgramVerdict.BLOCKED
    assert res.is_valid is False
    assert "exceeds max roadmap boundary" in res.reason


def test_pg1_03_exceeding_track_b_boundary_returns_blocked() -> None:
    """PG1-03 — Attempting to run Sprint K2 on Track B returns BLOCKED (INV-PROGRAM-01)."""
    res = verify_program_roadmap_lock(requested_track="B", requested_sprint="K2")
    assert res.state == ProgramLockState.BLOCKED
    assert res.verdict == ProgramVerdict.BLOCKED
    assert res.is_valid is False
    assert "exceeds max roadmap boundary" in res.reason


def test_pg1_04_forbidden_sub_sprint_suffix_returns_blocked() -> None:
    """PG1-04 — Sub-sprint suffix creation (e.g. F12-FIX, F12-HARDENING) returns BLOCKED (INV-SPEC-01)."""
    res_fix = verify_program_roadmap_lock(requested_track="C", requested_sprint="F12-FIX")
    assert res_fix.state == ProgramLockState.BLOCKED
    assert "INV-SPEC-01" in res_fix.reason

    res_post = verify_program_roadmap_lock(requested_track="C", requested_sprint="F12-POST")
    assert res_post.state == ProgramLockState.BLOCKED
    assert "INV-SPEC-01" in res_post.reason


def test_pg1_05_missing_roadmap_lock_fails_closed(tmp_path: Path) -> None:
    """PG1-05 — Non-existent lock path fails closed to BLOCKED (INV-PROGRAM-02)."""
    missing_lock = tmp_path / "missing.json"
    res = verify_program_roadmap_lock(roadmap_lock_path=missing_lock)
    assert res.state == ProgramLockState.BLOCKED
    assert res.verdict == ProgramVerdict.BLOCKED
    assert res.is_valid is False


def test_pg1_06_malformed_roadmap_lock_fails_closed(tmp_path: Path) -> None:
    """PG1-06 — Malformed JSON lock file fails closed to BLOCKED (INV-PROGRAM-02)."""
    bad_lock = tmp_path / "bad.json"
    bad_lock.write_text("{invalid json", encoding="utf-8")

    res = verify_program_roadmap_lock(roadmap_lock_path=bad_lock)
    assert res.state == ProgramLockState.BLOCKED
    assert res.verdict == ProgramVerdict.BLOCKED
    assert res.is_valid is False


def test_pg1_07_all_tracks_completed_returns_platform_certified(tmp_path: Path) -> None:
    """PG1-07 — When all 5 tracks are marked COMPLETE, returns KARSASEC_PLATFORM_CERTIFIED."""
    complete_lock = tmp_path / "complete_lock.json"
    complete_lock.write_text(
        json.dumps({
            "program": "KarsaSec",
            "tracks": {
                "A": {"status": "COMPLETE"},
                "B": {"status": "COMPLETE"},
                "C": {"status": "COMPLETE"},
                "D": {"status": "COMPLETE"},
                "E": {"status": "COMPLETE"},
            },
        }),
        encoding="utf-8",
    )

    res = verify_program_roadmap_lock(roadmap_lock_path=complete_lock)
    assert res.state == ProgramLockState.COMPLETED
    assert res.verdict == ProgramVerdict.KARSASEC_PLATFORM_CERTIFIED
    assert res.is_valid is True


def test_pg1_08_deterministic_program_evaluation() -> None:
    """PG1-08 — Program evaluation is 100% deterministic across 100 runs (INV-PROGRAM-05)."""
    engine = ProgramGovernanceEngine()
    first = engine.validate_sprint_execution("C", "F13")

    for _ in range(100):
        current = engine.validate_sprint_execution("C", "F13")
        assert current.state == first.state
        assert current.verdict == first.verdict
        assert current.reason == first.reason
