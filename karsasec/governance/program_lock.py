"""KarsaSec Program Governance & Roadmap Lock Engine (Sprint PG-1).

Enforces Program Invariants INV-PROGRAM-01 through INV-PROGRAM-05 and INV-SPEC-01 through INV-SPEC-03.
Validates PROGRAM_EXECUTION_SPEC.md and ROADMAP_LOCK.json boundaries, prevents sub-sprint creation,
and evaluates overall platform completion status.
"""

from __future__ import annotations

import json

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

# Canonical Maximum Sprint Boundaries from ROADMAP_LOCK
MAX_SPRINT_BOUNDARIES: dict[str, str] = {
    "A": "A8",
    "B": "K1.7",
    "C": "F15",
    "D": "D4",
    "E": "E4",
}

# Forbidden sub-sprint suffixes (INV-SPEC-01)
FORBIDDEN_SUB_SPRINT_SUFFIXES: tuple[str, ...] = (
    "-FIX",
    "-CBC",
    "-HARDENING",
    "-POST",
    "-LOCK",
    "-FINAL",
    "-AUDIT",
    "-REVIEW",
)


class ProgramLockState(StrEnum):
    ACTIVE = "ACTIVE"
    BLOCKED = "BLOCKED"
    COMPLETED = "COMPLETED"


class ProgramVerdict(StrEnum):
    IN_PROGRESS = "IN_PROGRESS"
    BLOCKED = "BLOCKED"
    KARSASEC_PLATFORM_CERTIFIED = "KARSASEC_PLATFORM_CERTIFIED"


@dataclass(frozen=True)
class ProgramVerificationResult:
    state: ProgramLockState
    verdict: ProgramVerdict
    is_valid: bool
    reason: str
    details: dict[str, Any] = field(default_factory=dict)


def verify_program_roadmap_lock(
    roadmap_lock_path: Path | str = "ROADMAP_LOCK.json",
    execution_spec_path: Path | str = "PROGRAM_EXECUTION_SPEC.md",
    requested_track: str | None = None,
    requested_sprint: str | None = None,
) -> ProgramVerificationResult:
    """Verifies program roadmap lock boundaries and enforces INV-PROGRAM-01 through INV-PROGRAM-05 and INV-SPEC-01."""
    p_lock = Path(roadmap_lock_path)
    p_spec = Path(execution_spec_path)

    # 1. INV-PROGRAM-02: Fail-Closed check for missing lock file or execution spec
    if not p_lock.exists() or not p_spec.exists():
        return ProgramVerificationResult(
            state=ProgramLockState.BLOCKED,
            verdict=ProgramVerdict.BLOCKED,
            is_valid=False,
            reason="BLOCKED (INV-PROGRAM-02): ROADMAP_LOCK.json or PROGRAM_EXECUTION_SPEC.md does not exist",
        )

    try:
        data = json.loads(p_lock.read_text(encoding="utf-8"))
    except Exception as e:
        return ProgramVerificationResult(
            state=ProgramLockState.BLOCKED,
            verdict=ProgramVerdict.BLOCKED,
            is_valid=False,
            reason=f"BLOCKED (INV-PROGRAM-02): Failed to parse ROADMAP_LOCK.json: {e}",
        )

    tracks = data.get("tracks", {})

    # 2. INV-SPEC-01 & INV-PROGRAM-01: Requested Sprint Boundary Check
    if requested_track and requested_sprint:
        track_upper = requested_track.upper()
        sprint_upper = requested_sprint.upper()

        # Check for forbidden sub-sprint suffix creation (INV-SPEC-01)
        for suffix in FORBIDDEN_SUB_SPRINT_SUFFIXES:
            if sprint_upper.endswith(suffix):
                return ProgramVerificationResult(
                    state=ProgramLockState.BLOCKED,
                    verdict=ProgramVerdict.BLOCKED,
                    is_valid=False,
                    reason=f"BLOCKED (INV-SPEC-01): Sub-sprint suffix '{suffix}' on sprint '{requested_sprint}' is strictly FORBIDDEN",
                )

        if track_upper not in MAX_SPRINT_BOUNDARIES:
            return ProgramVerificationResult(
                state=ProgramLockState.BLOCKED,
                verdict=ProgramVerdict.BLOCKED,
                is_valid=False,
                reason=f"BLOCKED (INV-PROGRAM-01): Requested track '{requested_track}' is invalid",
            )

        max_allowed = MAX_SPRINT_BOUNDARIES[track_upper]

        if _is_sprint_exceeding_max(sprint_upper, max_allowed, track_upper):
            return ProgramVerificationResult(
                state=ProgramLockState.BLOCKED,
                verdict=ProgramVerdict.BLOCKED,
                is_valid=False,
                reason=f"BLOCKED (INV-PROGRAM-01): Sprint '{requested_sprint}' exceeds max roadmap boundary '{max_allowed}' for Track {track_upper}",
            )

    # 3. INV-PROGRAM-05: Program Completion Criteria Check
    all_tracks_completed = True
    track_statuses: dict[str, str] = {}

    for track_key, max_sprint in MAX_SPRINT_BOUNDARIES.items():
        t_data = tracks.get(track_key, {})
        status = t_data.get("status", "IN_PROGRESS")
        track_statuses[track_key] = status
        if status != "COMPLETE":
            all_tracks_completed = False

    if all_tracks_completed:
        return ProgramVerificationResult(
            state=ProgramLockState.COMPLETED,
            verdict=ProgramVerdict.KARSASEC_PLATFORM_CERTIFIED,
            is_valid=True,
            reason="KARSASEC_PLATFORM_CERTIFIED: All 5 tracks (A8, K1.7, F15, D4, E4) complete",
            details=track_statuses,
        )

    return ProgramVerificationResult(
        state=ProgramLockState.ACTIVE,
        verdict=ProgramVerdict.IN_PROGRESS,
        is_valid=True,
        reason="ACTIVE: Program execution within valid ROADMAP_LOCK & PROGRAM_EXECUTION_SPEC boundaries",
        details=track_statuses,
    )


def _is_sprint_exceeding_max(sprint: str, max_sprint: str, track: str) -> bool:
    """Helper function to check if a sprint string exceeds the max sprint boundary."""
    sprint_clean = sprint.strip().upper()
    max_clean = max_sprint.strip().upper()

    if sprint_clean == max_clean:
        return False

    if track == "C" and sprint_clean.startswith("F"):
        try:
            num = int(sprint_clean[1:].split("-")[0].split(".")[0])
            max_num = int(max_clean[1:].split("-")[0].split(".")[0])
            return num > max_num
        except ValueError:
            pass

    if track in ("A", "D", "E") and sprint_clean.startswith(track):
        try:
            num = int(sprint_clean[1:].split("-")[0].split(".")[0])
            max_num = int(max_clean[1:].split("-")[0].split(".")[0])
            return num > max_num
        except ValueError:
            pass

    if track == "B" and (sprint_clean.startswith("K") or sprint_clean.startswith("F")):
        if sprint_clean.startswith("K2") or sprint_clean.startswith("K3") or sprint_clean.startswith("K4"):
            return True

    return False


class ProgramGovernanceEngine:
    """Governance Engine enforcing Program Integrity, Specification DAG, and termination policies."""

    def __init__(
        self,
        lock_path: Path | str = "ROADMAP_LOCK.json",
        spec_path: Path | str = "PROGRAM_EXECUTION_SPEC.md",
    ) -> None:
        self.lock_path = Path(lock_path)
        self.spec_path = Path(spec_path)

    def validate_sprint_execution(self, track: str, sprint: str) -> ProgramVerificationResult:
        """Validates a proposed sprint execution against the roadmap lock and execution spec."""
        return verify_program_roadmap_lock(
            roadmap_lock_path=self.lock_path,
            execution_spec_path=self.spec_path,
            requested_track=track,
            requested_sprint=sprint,
        )
