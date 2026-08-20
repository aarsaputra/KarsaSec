"""Source Snapshot & TOCTOU Defense Model for KarsaSec AI Engine (Sprint E13-4).

Captures exact per-file and aggregate SHA-256 hashes for target files prior to patch application.

Enforces Security Invariants:
  - H2: TOCTOU Source Snapshot Protection (Per-file SHA256 + Aggregate hash).
  - H9: Path Traversal & Symlink Defense (Canonical resolution relative to repository root).
  - H18: Repository Identity Binding.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, UTC
import hashlib
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class FileSnapshot:
    """Immutable snapshot of a single target file's state."""

    relative_path: str
    file_size: int
    sha256: str
    exists: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "relative_path": self.relative_path,
            "file_size": self.file_size,
            "sha256": self.sha256,
            "exists": self.exists,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FileSnapshot:
        return cls(
            relative_path=data["relative_path"],
            file_size=data["file_size"],
            sha256=data["sha256"],
            exists=data["exists"],
        )


@dataclass(frozen=True, slots=True)
class SourceSnapshot:
    """Immutable snapshot of target files across a repository root."""

    repository_root: str
    file_snapshots: tuple[FileSnapshot, ...]
    aggregate_hash: str
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "repository_root": self.repository_root,
            "file_snapshots": [f.to_dict() for f in self.file_snapshots],
            "aggregate_hash": self.aggregate_hash,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SourceSnapshot:
        files = tuple(FileSnapshot.from_dict(f) for f in data.get("file_snapshots", []))
        return cls(
            repository_root=data["repository_root"],
            file_snapshots=files,
            aggregate_hash=data["aggregate_hash"],
            created_at=data["created_at"],
        )

    @staticmethod
    def compute_aggregate_hash(file_snapshots: tuple[FileSnapshot, ...]) -> str:
        """Compute canonical aggregate hash over sorted per-file records."""
        sorted_snaps = sorted(file_snapshots, key=lambda f: f.relative_path)
        records = []
        for f in sorted_snaps:
            norm_rel = f.relative_path.replace("\\", "/")
            records.append(f"{norm_rel}:{f.sha256}:{f.file_size}:{f.exists}")
        raw = "|".join(records)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @classmethod
    def capture(
        cls,
        repository_root: Path | str,
        target_files: tuple[str, ...],
        created_at: str | None = None,
    ) -> SourceSnapshot:
        """Capture per-file and aggregate SHA-256 snapshot for target files.

        Strictly canonicalizes paths relative to repository_root to prevent traversal/symlink escapes (H9).
        """
        repo_path = Path(repository_root).resolve()
        now_iso = created_at or datetime.now(UTC).isoformat()
        snaps: list[FileSnapshot] = []

        for target_rel in target_files:
            norm_rel = target_rel.replace("\\", "/")
            # Path Traversal Guard (H9)
            target_path = (repo_path / norm_rel).resolve()
            try:
                if not target_path.is_relative_to(repo_path):
                    raise ValueError(f"Path traversal detected: '{target_rel}' resolves outside '{repo_path}'.")
            except AttributeError:
                # Fallback for older python versions if any
                if repo_path not in target_path.parents and target_path != repo_path:
                    raise ValueError(f"Path traversal detected: '{target_rel}' resolves outside '{repo_path}'.")

            if target_path.is_symlink():
                # Verify symlink target stays within repo_path
                resolved_sym = target_path.resolve()
                if not resolved_sym.is_relative_to(repo_path):
                    raise ValueError(f"Symlink escape detected: '{target_rel}' points outside '{repo_path}'.")

            if target_path.exists() and target_path.is_file():
                content = target_path.read_bytes()
                h = hashlib.sha256(content).hexdigest()
                snaps.append(
                    FileSnapshot(
                        relative_path=norm_rel,
                        file_size=len(content),
                        sha256=h,
                        exists=True,
                    )
                )
            else:
                snaps.append(
                    FileSnapshot(
                        relative_path=norm_rel,
                        file_size=0,
                        sha256="MISSING",
                        exists=False,
                    )
                )

        file_tuple = tuple(snaps)
        agg_hash = cls.compute_aggregate_hash(file_tuple)
        return cls(
            repository_root=str(repo_path),
            file_snapshots=file_tuple,
            aggregate_hash=agg_hash,
            created_at=now_iso,
        )

    def verify_matches(self, other: SourceSnapshot) -> tuple[bool, str]:
        """Verify that current snapshot matches another snapshot per-file and aggregate."""
        if self.aggregate_hash != other.aggregate_hash:
            return False, "AGGREGATE_HASH_MISMATCH: Repository state has changed since approval (TOCTOU violation)."

        self_dict = {f.relative_path: f for f in self.file_snapshots}
        other_dict = {f.relative_path: f for f in other.file_snapshots}

        if set(self_dict.keys()) != set(other_dict.keys()):
            return False, "FILE_LIST_MISMATCH: Target files differ between snapshots."

        for rel_path, self_snap in self_dict.items():
            other_snap = other_dict[rel_path]
            if self_snap.sha256 != other_snap.sha256:
                return (
                    False,
                    f"FILE_MUTATED: File '{rel_path}' hash modified from {other_snap.sha256[:8]} to {self_snap.sha256[:8]}.",
                )
            if self_snap.exists != other_snap.exists:
                return False, f"FILE_EXISTENCE_CHANGED: File '{rel_path}' existence changed."

        return True, "MATCH"
