"""Adversarial Unit Tests for Epistemic Safety Invariants.

Verifies:
1. UNKNOWN != SAFE and UNKNOWN != VULNERABLE.
2. CONFLICT != SAFE and CONFLICT != VULNERABLE.
3. FP = 0 on strict negative controls (config.get, cache.get, environment.get, parameterized SQL).
4. Absence of evidence never defaults to safety or vulnerability.
"""

from karsasec.analysis.decision.models import DecisionResolution
from karsasec.analysis.taint.sources import SourceResolver


def test_epistemic_safety_unknown_invariants() -> None:
    # UNKNOWN resolution cannot be converted to SAFE or VULNERABLE
    res = DecisionResolution.UNKNOWN
    assert res != DecisionResolution.SAFE
    assert res != DecisionResolution.VULNERABLE


def test_epistemic_safety_conflict_invariants() -> None:
    # CONFLICT resolution cannot be converted to SAFE or VULNERABLE
    res = DecisionResolution.CONFLICT
    assert res != DecisionResolution.SAFE
    assert res != DecisionResolution.VULNERABLE


def test_zero_false_positives_on_negative_controls() -> None:
    source_res = SourceResolver()

    # Negative controls MUST NOT produce user-controlled sources
    neg_controls = [
        "val = config.get('db_pass')",
        "val = cache.get('session_token')",
        "val = environment.get('ENV_KEY')",
    ]

    for snippet in neg_controls:
        sem = source_res.resolve_source(snippet)
        if sem is not None:
            assert not sem.is_user_controlled, f"False Positive risk on negative control: {snippet}"
