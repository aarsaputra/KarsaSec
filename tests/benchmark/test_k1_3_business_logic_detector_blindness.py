"""K1.3 Business Logic Detector Blindness Test Suite (Task K1.3)."""

import json
from pathlib import Path

from karsasec.analysis.taint.business_logic import BusinessLogicAnalyzer


def test_biz_detector_blindness_metadata_isolation() -> None:
    manifest_p = Path("benchmarks/k1/manifest.json")
    with open(manifest_p, encoding="utf-8") as f:
        manifest = json.load(f)

    analyzer = BusinessLogicAnalyzer()
    biz_cases = [c for c in manifest["cases"] if "biz" in c["case_id"] or "business" in c["case_id"]]

    for case in biz_cases:
        code = Path(case["source_file"]).read_text(encoding="utf-8")

        # 1. Standard execution
        res1 = analyzer.analyze_code(code, case["language"])

        # 2. Execution with zero contextual parameters
        res2 = analyzer.analyze_code(code)

        assert len(res1) == len(res2)
        if res1:
            assert res1[0].rule_id == res2[0].rule_id
