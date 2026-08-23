"""K1.6 Corpus & Baseline Snapshot Cryptographic Integrity Test Suite.

Verifies INV-K1.6-01, INV-K1.6-03, and INV-K1.6-11 against k1_4_provenance.json.
"""

import hashlib
import json
from pathlib import Path


def test_k1_6_original_corpus_and_baseline_provenance_integrity() -> None:
    manifest_p = Path("benchmarks/k1/manifest.json")
    holdout_p = Path("benchmarks/k1/holdout_manifest.json")
    snapshot_p = Path("benchmarks/k1/baseline/k1_4_findings.json")
    prov_p = Path("benchmarks/k1/baseline/k1_4_provenance.json")

    assert manifest_p.exists(), "manifest.json missing"
    assert holdout_p.exists(), "holdout_manifest.json missing"
    assert snapshot_p.exists(), "baseline/k1_4_findings.json missing"
    assert prov_p.exists(), "baseline/k1_4_provenance.json missing"

    with open(prov_p, encoding="utf-8") as f:
        prov = json.load(f)

    assert prov["schema_version"] == "K1.6-1"
    assert prov["baseline_version"] == "K1.4"
    assert prov["case_count"] == 40

    manifest_hash = hashlib.sha256(manifest_p.read_bytes()).hexdigest()
    holdout_hash = hashlib.sha256(holdout_p.read_bytes()).hexdigest()
    findings_hash = hashlib.sha256(snapshot_p.read_bytes()).hexdigest()

    assert manifest_hash == prov["manifest_sha256"], "manifest.json SHA256 mismatch against provenance record"
    assert holdout_hash == prov["holdout_manifest_sha256"], "holdout_manifest.json SHA256 mismatch against provenance record"
    assert findings_hash == prov["findings_sha256"], "k1_4_findings.json SHA256 mismatch against provenance record"

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
