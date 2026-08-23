"""Deterministic Rule Expansion Module (INV-G5.4-07).

Verifies that rule-loading permutations produce 100% deterministic, order-invariant findings.
"""

from typing import Any


def canonical_findings(findings: list[dict[str, Any]] | dict[str, Any]) -> list[tuple[str, str]]:
    """Canonicalizes findings into a deterministic list of sorted tuples."""
    if isinstance(findings, dict):
        return sorted([(str(k), str(v)) for k, v in findings.items()])

    canonical = []
    for f in findings:
        vuln_class = f.get("vulnerability_class", f.get("rule_id", "UNKNOWN"))
        verdict = f.get("verdict", f.get("status", "UNKNOWN"))
        canonical.append((str(vuln_class), str(verdict)))
    return sorted(canonical)


def verify_rule_order_determinism(
    runner_fn: Any, source_code: str, language: str, framework: str, rule_sets: list[list[str]]
) -> dict[str, Any]:
    """Runs runner_fn across multiple rule order permutations and checks for equality."""
    if not rule_sets:
        return {"status": "PASS", "deterministic": True}

    baseline_canonical = None
    for idx, rset in enumerate(rule_sets):
        # Simulating running detector with specific rule order
        raw = runner_fn(source_code, language, framework, rset)
        curr_canonical = canonical_findings(raw.get("findings", []))

        if baseline_canonical is None:
            baseline_canonical = curr_canonical
        elif curr_canonical != baseline_canonical:
            return {
                "status": "G5.4_DETERMINISM_FAILURE",
                "deterministic": False,
                "mismatch_permutation_index": idx,
                "baseline": baseline_canonical,
                "actual": curr_canonical,
            }

    return {
        "status": "PASS",
        "deterministic": True,
        "permutations_tested": len(rule_sets),
    }
