"""Real Cross-Dataset Adapter Runner & Evaluation (INVARIANT G5.1-05 & G5.1-06).

Executes canonical dataset manifests through BlindDetectorRunner and IndependentEvaluator.
Does NOT hardcode TP/TN/FP/FN in result dictionaries. Unexecuted datasets are marked NOT_EXECUTED.
"""

from typing import Any

from karsasec.benchmark.blind_runner import BlindDetectorRunner
from karsasec.benchmark.independent_evaluator import IndependentEvaluator


class CrossDatasetRunner:
    """Runner for real cross-dataset evaluation."""

    def __init__(self) -> None:
        self.detector = BlindDetectorRunner()
        self.evaluator = IndependentEvaluator()

    def run_dataset_manifest(self, dataset_name: str, manifest: dict[str, Any], tier: str = "SILVER") -> dict[str, Any]:
        """Executes a dataset manifest through the blind detector runner and independent evaluator.

        Args:
            dataset_name: Name of dataset (e.g. JuiceShop, VAmPI).
            manifest: Manifest dict containing cases list.
            tier: Quality tier ('GOLD', 'SILVER', 'BRONZE').

        Returns:
            dict containing executed dataset metrics and metadata.
        """
        cases = manifest.get("cases", [])
        if not cases:
            return {
                "dataset_name": dataset_name,
                "tier": tier,
                "status": "NOT_EXECUTED",
                "total_cases": 0,
            }

        raw_preds = []
        for c in cases:
            res = self.detector.analyze_blind(
                source_code=c.get("code_snippet", ""),
                language=c.get("language", "Java"),
                framework=c.get("framework", "Servlet"),
            )
            raw_preds.append({
                "case_id": c.get("vulnerability_id"),
                "source_provenance": res.get("source_provenance"),
                "findings": res.get("findings", {}),
            })

        metrics = self.evaluator.evaluate_manifest(raw_preds, manifest)
        return {
            "dataset_name": dataset_name,
            "tier": tier,
            "status": "EXECUTED",
            "metrics": metrics,
        }


def test_cross_dataset_execution_runner() -> None:
    runner = CrossDatasetRunner()

    sample_manifest = {
        "cases": [
            {
                "vulnerability_id": "JS_001",
                "CWE": "CWE-89",
                "expected_status": "VULNERABLE",
                "code_snippet": "req_data = request.args.get('id'); db.query('SELECT * FROM user WHERE id = ' + req_data);",
                "language": "Python",
                "framework": "Flask",
            },
            {
                "vulnerability_id": "JS_002",
                "CWE": "CWE-89",
                "expected_status": "SAFE",
                "code_snippet": "req_data = config.get('db_user'); db.query('SELECT * FROM user WHERE id = ' + req_data);",
                "language": "Python",
                "framework": "Flask",
            },
        ]
    }

    res = runner.run_dataset_manifest("JuiceShop_REST_Subset", sample_manifest, tier="SILVER")
    assert res["status"] == "EXECUTED"
    assert res["metrics"]["total_evaluated_cases"] == 2
    assert res["metrics"]["strict_precision"] == 1.0
    assert res["metrics"]["strict_recall"] == 1.0
