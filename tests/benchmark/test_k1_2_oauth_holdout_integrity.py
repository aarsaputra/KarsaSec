"""K1.2 OAuth Holdout Integrity & Non-Overlap Test Suite (Task K1.2)."""

import hashlib
import json
from pathlib import Path


def test_k1_2_oauth_holdout_manifest_sha256_verification() -> None:
    manifest_p = Path("benchmarks/k1/holdout_manifest.json")
    with open(manifest_p, encoding="utf-8") as f:
        manifest = json.load(f)

    oauth_holdout = [c for c in manifest["cases"] if "oauth" in c["case_id"]]
    assert len(oauth_holdout) == 1

    case = oauth_holdout[0]
    content = Path(case["source_file"]).read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    assert digest == case["sha256"]
    assert len(digest) == 64


def test_k1_2_oauth_holdout_textual_non_overlap() -> None:
    manifest_p = Path("benchmarks/k1/manifest.json")
    with open(manifest_p, encoding="utf-8") as f:
        manifest = json.load(f)

    dev_hashes = {c["sha256"] for c in manifest["cases"] if c["partition"] == "development"}

    holdout_manifest_p = Path("benchmarks/k1/holdout_manifest.json")
    with open(holdout_manifest_p, encoding="utf-8") as f:
        holdout_manifest = json.load(f)

    oauth_holdout_hashes = {c["sha256"] for c in holdout_manifest["cases"] if "oauth" in c["case_id"]}

    assert len(dev_hashes.intersection(oauth_holdout_hashes)) == 0
