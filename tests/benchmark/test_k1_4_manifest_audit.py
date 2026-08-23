"""K1.4 Manifest / Rule / Property Consistency Audit Test Suite (Task K1.4)."""

import hashlib
import json
from pathlib import Path

from karsasec.rules.patterns.k1.k1_registry import K1_CANONICAL_PROPERTIES


def test_k1_4_complete_40_case_manifest_consistency() -> None:
    with open("benchmarks/k1/manifest.json", encoding="utf-8") as f:
        m = json.load(f)
    with open("benchmarks/k1/holdout_manifest.json", encoding="utf-8") as f:
        hm = json.load(f)

    all_cases = m["cases"] + hm["cases"]
    seen_ids = set()
    unique_cases = []
    for c in all_cases:
        if c["case_id"] not in seen_ids:
            seen_ids.add(c["case_id"])
            unique_cases.append(c)

    assert len(unique_cases) == 40, f"Expected 40 unique K1 cases, got {len(unique_cases)}"

    rule_prop_map = {p.property_id: p for p in K1_CANONICAL_PROPERTIES}

    for case in unique_cases:
        # 1. Fixture existence
        p = Path(case["source_file"])
        assert p.exists(), f"Fixture file missing for {case['case_id']}"

        # 2. SHA256 match
        digest = hashlib.sha256(p.read_bytes()).hexdigest()
        assert digest == case["sha256"], f"SHA256 mismatch for {case['case_id']}"

        # 3. Expected status validity
        assert case["expected_status"] in ("TRUE_POSITIVE", "TRUE_NEGATIVE")

        # 4. Property mapping check if TP
        if case["expected_status"] == "TRUE_POSITIVE":
            prop = case["expected_property"]
            assert prop in rule_prop_map, f"Unrecognized TP property {prop} in {case['case_id']}"
