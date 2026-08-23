"""Unit tests verifying Determinism & Rule Order Invariance (INV-G5.4-07)."""

from karsasec.benchmark.deterministic_expansion import (
    canonical_findings,
    verify_rule_order_determinism,
)


def mock_runner(code: str, lang: str, fw: str, rule_set: list[str]) -> dict:
    # Rule set order should NOT affect output
    return {"findings": {"SQL_INJECTION": "VULNERABLE", "XSS": "SAFE"}}


def test_canonical_findings_ordering() -> None:
    f1 = {"XSS": "SAFE", "SQL_INJECTION": "VULNERABLE"}
    f2 = {"SQL_INJECTION": "VULNERABLE", "XSS": "SAFE"}
    assert canonical_findings(f1) == canonical_findings(f2)


def test_rule_order_determinism_pass() -> None:
    permutations = [
        ["R1", "R2", "R3"],
        ["R3", "R1", "R2"],
        ["R2", "R3", "R1"],
    ]
    res = verify_rule_order_determinism(mock_runner, "code", "PHP", "DVWA", permutations)
    assert res["status"] == "PASS"
    assert res["deterministic"] is True
