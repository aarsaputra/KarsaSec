"""K1.4 Cross-Pack Isolation Invariants Test Suite (Task K1.4)."""

import json
from pathlib import Path

from karsasec.analysis.taint.k1_integrated import K1IntegratedAnalyzer, analyze_k1


def test_inv_k1_4_cross_pack_isolation() -> None:
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

    analyzer = K1IntegratedAnalyzer()

    for case in cases:
        code = Path(case["source_file"]).read_text(encoding="utf-8")
        cid = case["case_id"]

        findings = analyze_k1(code)

        if "jwt" in cid:
            # INV-K1.4-01: JWT fixtures must not produce OAuth or Business Logic findings
            for f in findings:
                assert f.knowledge_pack == "JWT", f"Cross-pack leakage in {cid}: found {f.knowledge_pack}"
        elif "oauth" in cid:
            # INV-K1.4-02: OAuth fixtures must not produce JWT or Business Logic findings
            for f in findings:
                assert f.knowledge_pack == "OAuth", f"Cross-pack leakage in {cid}: found {f.knowledge_pack}"
        elif "biz" in cid:
            # INV-K1.4-03: Business Logic fixtures must not produce JWT or OAuth findings
            for f in findings:
                assert f.knowledge_pack == "Business Logic", f"Cross-pack leakage in {cid}: found {f.knowledge_pack}"


def test_inv_k1_4_pack_removal_invariance() -> None:
    with open("benchmarks/k1/manifest.json", encoding="utf-8") as f:
        m = json.load(f)

    analyzer = K1IntegratedAnalyzer()
    dev_cases = [c for c in m["cases"] if c["partition"] == "development"]

    for case in dev_cases:
        code = Path(case["source_file"]).read_text(encoding="utf-8")

        full_findings = analyzer.analyze_code(code, enabled_packs=("JWT", "OAuth", "Business Logic"))
        jwt_oauth_findings = analyzer.analyze_code(code, enabled_packs=("JWT", "OAuth"))

        jwt_oauth_in_full = [f for f in full_findings if f.knowledge_pack in ("JWT", "OAuth")]
        assert len(jwt_oauth_in_full) == len(jwt_oauth_findings)
