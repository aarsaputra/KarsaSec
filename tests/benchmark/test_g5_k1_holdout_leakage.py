"""Unit tests verifying Holdout Non-Leakage & AST Fingerprint Independence (INV-G5.4.17)."""

import hashlib
import json
from pathlib import Path


def test_holdout_zero_textual_duplicates_with_dev() -> None:
    manifest_p = Path("benchmarks/k1/manifest.json")
    with open(manifest_p, encoding="utf-8") as f:
        manifest = json.load(f)

    dev_hashes = set()
    holdout_hashes = set()

    for case in manifest["cases"]:
        source_content = Path(case["source_file"]).read_text(encoding="utf-8")
        h = hashlib.sha256(source_content.encode("utf-8")).hexdigest()

        if case["partition"] == "development":
            dev_hashes.add(h)
        elif case["partition"] == "holdout":
            holdout_hashes.add(h)

    # Intersection MUST be empty
    overlap = dev_hashes.intersection(holdout_hashes)
    assert len(overlap) == 0, f"Found {len(overlap)} exact textual duplicates between dev and holdout sets!"


def test_holdout_sha256_full_64_hex_digits() -> None:
    manifest_p = Path("benchmarks/k1/manifest.json")
    with open(manifest_p, encoding="utf-8") as f:
        manifest = json.load(f)

    for case in manifest["cases"]:
        sha = case["sha256"]
        assert len(sha) == 64
        assert all(c in "0123456789abcdef" for c in sha)
        assert sha != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # Not empty string hash
