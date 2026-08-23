"""Knowledge Pack Regression Checker (INV-G5.4-04).

Ensures that Knowledge Pack Expansion (K1) does not degrade existing baseline metrics.
"""

from typing import Any


def compare_metrics(baseline: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    """Compares candidate metrics against baseline metrics for regressions.

    Metrics checked:
    - precision
    - recall
    - specificity
    - fpr (false positive rate)
    - edc (epistemic decision correctness)
    """
    if not baseline or not candidate:
        return {
            "status": "INSUFFICIENT_DATA",
            "has_regression": True,
            "regressions": ["Missing metric dictionaries for baseline or candidate."],
        }

    regressions = []
    keys_to_check = ["precision", "recall", "specificity", "edc"]

    for k in keys_to_check:
        b_val = baseline.get(k)
        c_val = candidate.get(k)
        if b_val is None or c_val is None:
            return {
                "status": "INSUFFICIENT_DATA",
                "has_regression": True,
                "regressions": [f"Missing metric '{k}'."],
            }
        if c_val < b_val - 1e-6:
            regressions.append(f"Metric '{k}' degraded from {b_val} to {c_val}.")

    b_fpr = baseline.get("fpr")
    c_fpr = candidate.get("fpr")
    if b_fpr is not None and c_fpr is not None:
        if c_fpr > b_fpr + 1e-6:
            regressions.append(f"Metric 'fpr' increased from {b_fpr} to {c_fpr}.")

    if regressions:
        return {
            "status": "KNOWLEDGE_EXPANSION_REGRESSION",
            "has_regression": True,
            "regressions": regressions,
        }

    return {
        "status": "PASS",
        "has_regression": False,
        "regressions": [],
    }
