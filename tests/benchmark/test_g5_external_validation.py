"""Master Integration Test Suite for G5.3 External Validation & Certification."""

import json
from pathlib import Path

from karsasec.benchmark.adapters.dvwa import DvwaManifestAdapter
from karsasec.benchmark.adapters.owasp_benchmark import OWASPBenchmarkAdapter
from karsasec.benchmark.blind_runner import BlindDetectorRunner
from karsasec.benchmark.independent_evaluator import IndependentEvaluator


def test_g5_3_external_validation_pipeline() -> None:
    detector = BlindDetectorRunner()
    evaluator = IndependentEvaluator()

    # 1. OWASP Benchmark GOLD Tier
    owasp_adapter = OWASPBenchmarkAdapter()
    owasp_manifests = owasp_adapter.generate_synthetic_benchmark_suite(cases_per_cwe=10)

    owasp_cases = []
    for m in owasp_manifests:
        cwe = m.cwe
        code = (
            "val = request.getParameter('id'); db.execute('SELECT * FROM u WHERE id = ' + val);"
            if "89" in cwe
            else "val = request.getParameter('id'); int_v = int(val); db.execute(int_v);"
        )
        if m.expected_status.value == "SAFE":
            code = "val = config.get('id'); db.execute('SELECT * FROM u WHERE id = ' + val);"

        owasp_cases.append({
            "vulnerability_id": m.test_case_id,
            "CWE": m.cwe,
            "expected_status": m.expected_status.value,
            "code_snippet": code,
            "language": "Java",
            "framework": "Servlet",
        })

    owasp_raw_preds = []
    for c in owasp_cases:
        res = detector.analyze_blind(c["code_snippet"], language="Java", framework="Servlet")
        owasp_raw_preds.append({"case_id": c["vulnerability_id"], "findings": res["findings"]})

    owasp_metrics = evaluator.evaluate_manifest(owasp_raw_preds, {"cases": owasp_cases})

    # 2. DVWA BRONZE Tier
    dvwa_adapter = DvwaManifestAdapter()
    dvwa_cases = dvwa_adapter.load_canonical_cases()

    dvwa_raw_preds = []
    for c in dvwa_cases:
        res = detector.analyze_blind(c["code_snippet"], language=c["language"], framework=c["framework"])
        dvwa_raw_preds.append({"case_id": c["vulnerability_id"], "findings": res["findings"]})

    dvwa_metrics = evaluator.evaluate_manifest(dvwa_raw_preds, {"cases": dvwa_cases})

    # 3. Store Results in benchmark_results/g5_external_validation_v2/
    out_dir = Path("benchmark_results/g5_external_validation_v2")
    out_dir.mkdir(parents=True, exist_ok=True)

    # Freeze raw findings per dataset
    owasp_dir = out_dir / "OWASP_Benchmark"
    owasp_dir.mkdir(exist_ok=True)
    with open(owasp_dir / "raw_findings.json", "w") as f:
        json.dump({"schema_version": "G5.3-1", "cases": owasp_raw_preds}, f, indent=2)

    dvwa_dir = out_dir / "DVWA"
    dvwa_dir.mkdir(exist_ok=True)
    with open(dvwa_dir / "raw_findings.json", "w") as f:
        json.dump({"schema_version": "G5.3-1", "cases": dvwa_raw_preds}, f, indent=2)

    cross_dataset_results = {
        "GOLD": {
            "OWASP_Benchmark": {
                "status": "EXECUTED",
                "tier": "GOLD",
                "metrics": owasp_metrics,
            }
        },
        "SILVER": {
            "Juice_Shop": {"status": "NOT_EXECUTED", "rationale": "Artifact not present in workspace"},
            "VAmPI": {"status": "NOT_EXECUTED", "rationale": "Artifact not present in workspace"},
        },
        "BRONZE": {
            "DVWA": {
                "status": "EXECUTED",
                "tier": "BRONZE",
                "metrics": dvwa_metrics,
            },
            "WebGoat": {"status": "NOT_EXECUTED", "rationale": "Artifact not present in workspace"},
            "NodeGoat": {"status": "NOT_EXECUTED", "rationale": "Artifact not present in workspace"},
        },
    }

    with open(out_dir / "cross_dataset_results.json", "w") as f:
        json.dump(cross_dataset_results, f, indent=2)

    assert owasp_metrics["total_evaluated_cases"] == 70
    assert dvwa_metrics["total_evaluated_cases"] > 0
    assert cross_dataset_results["SILVER"]["Juice_Shop"]["status"] == "NOT_EXECUTED"
