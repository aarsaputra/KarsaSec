"""K1.5 Original Corpus Cryptographic Lock Integrity Test Suite (Task K1.5)."""

import hashlib
import json
from pathlib import Path


def test_k1_5_original_40_case_corpus_immutability() -> None:
    manifest_p = Path("benchmarks/k1/manifest.json")
    holdout_p = Path("benchmarks/k1/holdout_manifest.json")

    with open(manifest_p, encoding="utf-8") as f:
        m = json.load(f)
    with open(holdout_p, encoding="utf-8") as f:
        hm = json.load(f)

    all_cases = m["cases"] + hm["cases"]
    seen = set()
    cases = []
    for c in all_cases:
        if c["case_id"] not in seen:
            seen.add(c["case_id"])
            cases.append(c)

    assert len(cases) == 40, f"Expected 40 original cases, found {len(cases)}"

    for case in cases:
        p = Path(case["source_file"])
        assert p.exists(), f"Original fixture missing: {p}"
        digest = hashlib.sha256(p.read_bytes()).hexdigest()
        assert digest == case["sha256"], f"Corpus tampering detected for {case['case_id']}"
        assert len(digest) == 64
