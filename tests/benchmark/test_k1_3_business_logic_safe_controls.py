"""K1.3 Business Logic Safe Controls Test Suite (Task K1.3)."""

import json
from pathlib import Path

from karsasec.analysis.taint.business_logic import BusinessLogicAnalyzer


def test_k1_3_biz_safe_controls_zero_false_positives() -> None:
    manifest_p = Path("benchmarks/k1/manifest.json")
    with open(manifest_p, encoding="utf-8") as f:
        manifest = json.load(f)

    analyzer = BusinessLogicAnalyzer()
    safe_cases = [c for c in manifest["cases"] if ("biz" in c["case_id"] or "business" in c["case_id"]) and c["expected_status"] == "TRUE_NEGATIVE"]
    assert len(safe_cases) >= 5

    for case in safe_cases:
        code = Path(case["source_file"]).read_text(encoding="utf-8")
        findings = analyzer.analyze_code(code, case["language"])
        assert len(findings) == 0, f"False positive generated for safe control {case['case_id']}"
