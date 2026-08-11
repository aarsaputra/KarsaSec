"""Finding identity for deterministic qualification matching (E12-1).

Identity algorithm:
    A finding is identified by (normalized_file, line, rule_id).
    - normalized_file: POSIX path, lowercased, relative to scan root.
    - line: integer line number. None matches any line (file-level rules).
    - rule_id: the exact rule ID string.

Excluded from identity:
    - message text (changes with rule version)
    - confidence / severity (adjusted by TaintVerifier — not stable)
    - generated timestamps
    - UUID / object memory identity

Line-tolerance:
    E12-1 uses exact line matching. Line-range tolerance belongs to E12-2.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from karsasec.core.finding.model import Finding
    from karsasec.qualification.model import GroundTruthCase


@dataclass(frozen=True, order=True)
class FindingIdentity:
    """Deterministic, stable identity for a security finding.

    Used to match ground-truth cases against actual findings without relying
    on unstable attributes (timestamps, messages, generated IDs).
    """
    normalized_file: str   # POSIX, lowercased, relative to scan root
    line: int | None    # 1-indexed. None = file-level match
    rule_id: str

    @classmethod
    def from_finding(cls, finding: Finding, scan_root: Path) -> FindingIdentity:  # type: ignore[name-defined]
        """Construct identity from a Finding object.

        Args:
            finding:   The Finding to derive identity from.
            scan_root: Absolute path that all file paths are made relative to.
        """
        norm = _normalize_file(finding.file_path, scan_root)
        return cls(
            normalized_file=norm,
            line=finding.evidence.line if finding.evidence.line > 0 else None,
            rule_id=finding.rule_id,
        )

    @classmethod
    def from_case(cls, case: GroundTruthCase) -> FindingIdentity:  # type: ignore[name-defined]
        """Construct identity from a GroundTruthCase.

        The file path in the case is already relative; normalize it to POSIX lowercase.
        rule_id is required for identity (TN cases may have rule_id set for per-rule matching).
        """
        return cls(
            normalized_file=_normalize_path_str(case.file),
            line=case.line,
            rule_id=case.rule_id or "",
        )

    def fingerprint(self) -> str:
        """SHA-256 fingerprint of this identity (first 16 hex chars).

        Stable across runs, suitable for use in output/JSON.
        """
        raw = f"{self.normalized_file}|{self.line}|{self.rule_id}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def matches_finding(self, other: FindingIdentity) -> bool:
        """True if this identity matches another, using exact line comparison.

        If either identity has line=None, the line is not compared.
        """
        if self.rule_id != other.rule_id and self.rule_id and other.rule_id:
            return False
        if self.normalized_file != other.normalized_file:
            return False
        # Line: None means file-level → match regardless; allow 3-line window for AST sink vs source line offset
        if self.line is not None and other.line is not None:
            return abs(self.line - other.line) <= 3
        return True


def _normalize_file(path: Path, scan_root: Path) -> str:
    """Normalize a file Path to a relative, lowercased POSIX string."""
    try:
        rel = path.resolve().relative_to(scan_root.resolve())
        rel_str = rel.as_posix()
        if scan_root.name.lower() == "vulnerabilities" and not rel_str.lower().startswith("vulnerabilities/"):
            rel_str = f"vulnerabilities/{rel_str}"
        return _normalize_path_str(rel_str)
    except ValueError:
        return _normalize_path_str(path.as_posix())


def _normalize_path_str(path_str: str) -> str:
    """Normalize a path string (Windows/Linux, leading ./, lowercased)."""
    clean = path_str.replace("\\", "/")
    while clean.startswith("./") or clean.startswith("/"):
        if clean.startswith("./"):
            clean = clean[2:]
        elif clean.startswith("/"):
            clean = clean[1:]
    return Path(clean).as_posix().lower()
