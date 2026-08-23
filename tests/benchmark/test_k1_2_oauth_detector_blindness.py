"""K1.2 OAuth Detector Blindness & Metadata Isolation Test Suite (Task K1.2)."""

import json
from pathlib import Path

from karsasec.analysis.taint.oauth import OAuthAnalyzer


def test_oauth_detector_blindness_metadata_isolation() -> None:
    manifest_p = Path("benchmarks/k1/manifest.json")
    with open(manifest_p, encoding="utf-8") as f:
        manifest = json.load(f)

    analyzer = OAuthAnalyzer()
    oauth_cases = [c for c in manifest["cases"] if "oauth" in c["case_id"]]

    for case in oauth_cases:
        code = Path(case["source_file"]).read_text(encoding="utf-8")

        # 1. Standard execution
        res1 = analyzer.analyze_code(code, case["language"])

        # 2. Execution with zero contextual parameters
        res2 = analyzer.analyze_code(code)

        assert len(res1) == len(res2)
        if res1:
            assert res1[0].rule_id == res2[0].rule_id
