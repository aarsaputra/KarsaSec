"""K1.4 Cryptographic Provenance & Holdout Non-Overlap Test Suite (Task K1.4)."""

import hashlib
import json
from pathlib import Path


def test_k1_4_all_40_cases_sha256_verification() -> None:
    with open("benchmarks/k1/manifest.json", encoding="utf-8") as f:
        m = json.load(f)
    with open("benchmarks/k1/holdout_manifest.json", encoding="utf-8") as f:
        hm = json.load(f)

    all_cases = m["cases"] + hm["cases"]
    seen = set()
    cases = []
    for c in all_cases:
        if c["case_id"] not in seen:
            seen.add(c["case_id"])
            cases.append(c)

    for case in cases:
        content = Path(case["source_file"]).read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        assert digest == case["sha256"]
        assert len(digest) == 64


def test_k1_4_dev_vs_holdout_zero_textual_overlap() -> None:
    with open("benchmarks/k1/manifest.json", encoding="utf-8") as f:
        m = json.load(f)
    with open("benchmarks/k1/holdout_manifest.json", encoding="utf-8") as f:
        hm = json.load(f)

    dev_hashes = {c["sha256"] for c in m["cases"] if c["partition"] == "development"}
    holdout_hashes = {c["sha256"] for c in hm["cases"]}

    assert len(dev_hashes.intersection(holdout_hashes)) == 0
