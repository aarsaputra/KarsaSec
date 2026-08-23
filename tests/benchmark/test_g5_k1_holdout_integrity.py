"""Unit tests verifying K1 Holdout Integrity & Anti-Leakage (INV-G5.4-10)."""

import hashlib
import json
from pathlib import Path


def test_holdout_manifest_sha256_verification() -> None:
    manifest_p = Path("benchmarks/k1/holdout_manifest.json")
    sha_p = Path("benchmarks/k1/holdout_manifest.sha256")

    assert manifest_p.exists()
    assert sha_p.exists()

    with open(manifest_p, encoding="utf-8") as f:
        content = f.read()

    expected_sha = sha_p.read_text().strip()
    actual_sha = hashlib.sha256(content.encode("utf-8")).hexdigest()

    assert actual_sha == expected_sha


def test_holdout_case_count_is_10() -> None:
    manifest_p = Path("benchmarks/k1/holdout_manifest.json")
    with open(manifest_p, encoding="utf-8") as f:
        data = json.load(f)

    assert data["holdout_count"] == 10
    assert len(data["cases"]) == 10
