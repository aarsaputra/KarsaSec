"""K1.6 Post-Certification Integrity & Drift Verification Engine.

Performs fail-closed verification of certification manifests, baseline hashes,
trust anchors, detached signatures, production scope immutability, and corpus integrity.
Provides release boundary enforcement guards (CertificationReleaseGuard).
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

# Hardcoded Certified Trust Anchor
K1_4_TRUST_ANCHOR_SHA256 = "f41f0e74d7e703cc60c4471b7fe944085b0cbcbb7d6c32612e5d5142cf0cbc48"


class CertificationIntegrityStatus(StrEnum):
    VALID = "VALID"
    DRIFTED = "DRIFTED"
    MISSING = "MISSING"
    INVALID = "INVALID"


class CertificationGateState(StrEnum):
    READY = "READY"
    BLOCKED = "BLOCKED"


@dataclass
class CertificationIntegrityResult:
    status: CertificationIntegrityStatus
    reason: str
    details: dict[str, Any] = field(default_factory=dict)

    def is_valid(self) -> bool:
        return self.status == CertificationIntegrityStatus.VALID


@dataclass(frozen=True)
class CertificationGateResult:
    state: CertificationGateState
    integrity_status: CertificationIntegrityStatus
    reason: str
    details: dict[str, Any] = field(default_factory=dict)

    def is_ready(self) -> bool:
        return self.state == CertificationGateState.READY


class CertificationReleaseGuard:
    """Monotonic Release Guard ensuring once BLOCKED, an execution context cannot become READY."""

    def __init__(self) -> None:
        self._state = CertificationGateState.READY
        self._last_result: CertificationGateResult | None = None

    def require_integrity(
        self,
        manifest_path: Path | str = "docs/g5_4_pre_knowledge_assurance/k1_6_certification_manifest.json",
        detached_sha_path: Path | str = "docs/g5_4_pre_knowledge_assurance/k1_6_certification_manifest.sha256",
        repo_root: Path | str = ".",
        check_git: bool = True,
    ) -> CertificationGateResult:
        if self._state == CertificationGateState.BLOCKED:
            return CertificationGateResult(
                state=CertificationGateState.BLOCKED,
                integrity_status=self._last_result.integrity_status if self._last_result else CertificationIntegrityStatus.INVALID,
                reason="Release boundary remains BLOCKED due to previous integrity failure",
                details=self._last_result.details if self._last_result else {},
            )

        try:
            res = verify_certification_integrity(manifest_path, detached_sha_path, repo_root, check_git)
        except Exception as e:
            gate_res = CertificationGateResult(
                state=CertificationGateState.BLOCKED,
                integrity_status=CertificationIntegrityStatus.INVALID,
                reason=f"Integrity verifier exception: {e}",
            )
            self._state = CertificationGateState.BLOCKED
            self._last_result = gate_res
            return gate_res

        if res.status != CertificationIntegrityStatus.VALID:
            gate_res = CertificationGateResult(
                state=CertificationGateState.BLOCKED,
                integrity_status=res.status,
                reason=f"Release boundary BLOCKED [{res.status}]: {res.reason}",
                details=res.details,
            )
            self._state = CertificationGateState.BLOCKED
            self._last_result = gate_res
            return gate_res

        gate_res = CertificationGateResult(
            state=CertificationGateState.READY,
            integrity_status=CertificationIntegrityStatus.VALID,
            reason="K1.6 certification integrity verified; release boundary READY",
            details=res.details,
        )
        self._last_result = gate_res
        return gate_res


def require_certification_integrity(
    manifest_path: Path | str = "docs/g5_4_pre_knowledge_assurance/k1_6_certification_manifest.json",
    detached_sha_path: Path | str = "docs/g5_4_pre_knowledge_assurance/k1_6_certification_manifest.sha256",
    repo_root: Path | str = ".",
    check_git: bool = True,
) -> CertificationGateResult:
    """Convenience function executing release boundary integrity verification."""
    guard = CertificationReleaseGuard()
    return guard.require_integrity(manifest_path, detached_sha_path, repo_root, check_git)


def sha256_file(path: Path) -> str:
    """Returns SHA256 hex digest of raw file bytes."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_git_diff(target_dir: str, repo_root: Path) -> bool:
    """Returns True if git diff on target_dir is EMPTY, else False."""
    try:
        res = subprocess.run(
            ["git", "diff", "--", target_dir],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=False,
        )
        return res.returncode == 0 and res.stdout.strip() == ""
    except Exception:
        return False


def verify_certification_integrity(
    manifest_path: Path | str = "docs/g5_4_pre_knowledge_assurance/k1_6_certification_manifest.json",
    detached_sha_path: Path | str = "docs/g5_4_pre_knowledge_assurance/k1_6_certification_manifest.sha256",
    repo_root: Path | str = ".",
    check_git: bool = True,
) -> CertificationIntegrityResult:
    """Performs fail-closed verification of certified state against repository artifacts."""
    m_path = Path(manifest_path)
    s_path = Path(detached_sha_path)
    r_root = Path(repo_root)

    # 1. Manifest file existence check
    if not m_path.exists():
        return CertificationIntegrityResult(
            status=CertificationIntegrityStatus.MISSING,
            reason=f"Certification manifest missing: {m_path}",
        )

    # 2. Detached signature existence & match check
    if not s_path.exists():
        return CertificationIntegrityResult(
            status=CertificationIntegrityStatus.MISSING,
            reason=f"Detached SHA256 record missing: {s_path}",
        )

    try:
        detached_content = s_path.read_text(encoding="utf-8").strip()
        expected_manifest_sha = detached_content.split()[0]
        actual_manifest_sha = sha256_file(m_path)
        if expected_manifest_sha != actual_manifest_sha:
            return CertificationIntegrityResult(
                status=CertificationIntegrityStatus.INVALID,
                reason=f"Detached manifest SHA256 mismatch: expected {expected_manifest_sha}, got {actual_manifest_sha}",
            )
    except Exception as e:
        return CertificationIntegrityResult(
            status=CertificationIntegrityStatus.INVALID,
            reason=f"Failed to read detached SHA256 signature: {e}",
        )

    # 3. Manifest schema & content validation
    try:
        manifest = json.loads(m_path.read_text(encoding="utf-8"))
    except Exception as e:
        return CertificationIntegrityResult(
            status=CertificationIntegrityStatus.INVALID,
            reason=f"Malformed manifest JSON: {e}",
        )

    if not isinstance(manifest, dict) or manifest.get("status") != "K1.6_FINAL_CERTIFIED":
        return CertificationIntegrityResult(
            status=CertificationIntegrityStatus.INVALID,
            reason="Invalid certification manifest status or structure",
        )

    # 4. Trust anchor verification
    trust_anchors = manifest.get("trust_anchors", {})
    manifest_anchor = trust_anchors.get("k1_4_provenance_sha256")
    if manifest_anchor != K1_4_TRUST_ANCHOR_SHA256:
        return CertificationIntegrityResult(
            status=CertificationIntegrityStatus.INVALID,
            reason=f"Trust anchor digest mismatch in manifest: expected {K1_4_TRUST_ANCHOR_SHA256}, got {manifest_anchor}",
        )

    # 5. Baseline artifact hashes check
    baselines = manifest.get("baseline", {})
    if not baselines:
        return CertificationIntegrityResult(
            status=CertificationIntegrityStatus.INVALID,
            reason="Manifest missing baseline artifact definitions",
        )

    for rel_path, expected_sha in baselines.items():
        artifact_p = r_root / rel_path
        if not artifact_p.exists():
            return CertificationIntegrityResult(
                status=CertificationIntegrityStatus.MISSING,
                reason=f"Certified baseline artifact missing: {rel_path}",
            )
        try:
            actual_sha = sha256_file(artifact_p)
            if actual_sha != expected_sha:
                return CertificationIntegrityResult(
                    status=CertificationIntegrityStatus.DRIFTED,
                    reason=f"Baseline SHA256 drift in {rel_path}: expected {expected_sha}, got {actual_sha}",
                )
        except Exception as e:
            return CertificationIntegrityResult(
                status=CertificationIntegrityStatus.INVALID,
                reason=f"Error hashing baseline artifact {rel_path}: {e}",
            )

    # 6. Production detector scope check
    if check_git:
        prod_scope = manifest.get("production_scope", {}).get("path", "karsasec/analysis/taint/")
        if not check_git_diff(prod_scope, r_root):
            return CertificationIntegrityResult(
                status=CertificationIntegrityStatus.DRIFTED,
                reason=f"Production detector modification detected in {prod_scope}",
            )

    # 7. Corpus scope verification
    corpus_files = manifest.get("corpus_scope", {}).get("manifest_files", [])
    for c_file in corpus_files:
        c_path = r_root / c_file
        if not c_path.exists():
            return CertificationIntegrityResult(
                status=CertificationIntegrityStatus.MISSING,
                reason=f"Corpus manifest file missing: {c_file}",
            )

    return CertificationIntegrityResult(
        status=CertificationIntegrityStatus.VALID,
        reason="K1.6 post-certification integrity successfully verified",
        details={
            "manifest_sha": actual_manifest_sha,
            "trust_anchor": K1_4_TRUST_ANCHOR_SHA256,
            "status": "K1.6_POST_CERTIFICATION_INTEGRITY_LOCKED",
        },
    )
