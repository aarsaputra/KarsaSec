"""K1.2 OAuth Safe Controls Test Suite (Task K1.2)."""

import json
from pathlib import Path

from karsasec.analysis.taint.oauth import OAuthAnalyzer


def test_k1_2_oauth_safe_controls_zero_false_positives() -> None:
    manifest_p = Path("benchmarks/k1/manifest.json")
    with open(manifest_p, encoding="utf-8") as f:
        manifest = json.load(f)

    analyzer = OAuthAnalyzer()
    safe_cases = [c for c in manifest["cases"] if "oauth" in c["case_id"] and c["expected_status"] == "TRUE_NEGATIVE"]
    assert len(safe_cases) >= 3

    for case in safe_cases:
        code = Path(case["source_file"]).read_text(encoding="utf-8")
        findings = analyzer.analyze_code(code, case["language"])
        assert len(findings) == 0, f"False positive generated for safe control {case['case_id']}"
