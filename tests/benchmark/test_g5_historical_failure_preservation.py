"""Unit tests verifying Historical DVWA Failure Preservation (INV-G5.4-12)."""

import json
from pathlib import Path


def test_historical_dvwa_failures_preserved() -> None:
    failures_p = Path("benchmark_results/g5_external_validation_v2/failures.json")
    assert failures_p.exists()

    with open(failures_p, encoding="utf-8") as f:
        failures = json.load(f)

    case_ids = {f["original_case_id"] for f in failures}
    assert "dvwa-exec-impossible-001" in case_ids
    assert "dvwa-exec-impossible-002" in case_ids

    # Verify detector was NOT modified to fix these historical failures
    for f in failures:
        assert f.get("detector_modified", False) is False
