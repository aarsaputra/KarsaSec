"""Unit tests verifying K1 Semantic Ground-Truth Realization & Safe Controls (INV-G5.4.13 & INV-G5.4.15)."""

import json
from pathlib import Path

from karsasec.benchmark.k1_semantic_oracle import analyze_fixture, compare_oracle_to_manifest


def test_no_k1_cases_are_pass_stubs() -> None:
    manifest_p = Path("benchmarks/k1/manifest.json")
    assert manifest_p.exists()

    with open(manifest_p, encoding="utf-8") as f:
        manifest = json.load(f)

    for case in manifest["cases"]:
        source_p = Path(case["source_file"])
        assert source_p.exists()
        content = source_p.read_text(encoding="utf-8").strip()

        # Reject any case that is merely a pass stub or empty comment
        assert content != "pass"
        assert "def handler(req):\n    pass" not in content
        assert len(content.splitlines()) >= 2


def test_independent_oracle_validates_semantic_ground_truth() -> None:
    manifest_p = Path("benchmarks/k1/manifest.json")
    with open(manifest_p, encoding="utf-8") as f:
        manifest = json.load(f)

    valid_matches = 0
    for case in manifest["cases"]:
        source_content = Path(case["source_file"]).read_text(encoding="utf-8")

        # 1. Stage 1: Analyze fixture with ZERO labels
        evidence = analyze_fixture(source_content)
        assert len(evidence.observed_properties) > 0 or len(evidence.evidence) > 0
        assert evidence.status_candidate != "UNKNOWN"

        # 2. Stage 2: Compare analyzer output against manifest independently
        res = compare_oracle_to_manifest(
            evidence,
            case["expected_property"],
            case["expected_status"],
            case_id=case["case_id"],
            fixture_id=case.get("semantic_fixture_id", "UNKNOWN"),
        )

        assert res.property_match is True
        assert res.semantic_status != "UNKNOWN"
        assert len(res.evidence) > 0
        valid_matches += 1

    assert valid_matches == 40


def test_safe_controls_exist_in_all_families() -> None:
    manifest_p = Path("benchmarks/k1/manifest.json")
    with open(manifest_p, encoding="utf-8") as f:
        manifest = json.load(f)

    categories = {"JWT": {"TP": 0, "TN": 0}, "OAUTH": {"TP": 0, "TN": 0}, "BUSINESS_LOGIC": {"TP": 0, "TN": 0}}

    for case in manifest["cases"]:
        cid = case["case_id"]
        if "jwt" in cid:
            cat = "JWT"
        elif "oauth" in cid:
            cat = "OAUTH"
        else:
            cat = "BUSINESS_LOGIC"

        if case["expected_status"] == "TRUE_POSITIVE":
            categories[cat]["TP"] += 1
        elif case["expected_status"] == "TRUE_NEGATIVE":
            categories[cat]["TN"] += 1

    for cat, counts in categories.items():
        assert counts["TP"] > 0, f"Category {cat} missing vulnerable fixtures"
        assert counts["TN"] > 0, f"Category {cat} missing safe controls"
