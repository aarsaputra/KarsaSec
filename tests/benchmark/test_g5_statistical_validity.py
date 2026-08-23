"""Unit tests for Wilson score confidence intervals and statistical functions."""

from karsasec.benchmark.statistics import wilson_interval


def test_wilson_interval_bounds() -> None:
    # Test perfect score (35/35)
    p, lower, upper = wilson_interval(35, 35)
    assert p == 1.0
    assert 0.89 <= lower <= 0.91
    assert upper == 1.0

    # Test 50% score (20/40)
    p2, lower2, upper2 = wilson_interval(20, 40)
    assert p2 == 0.5
    assert 0.34 <= lower2 <= 0.36
    assert 0.64 <= upper2 <= 0.66

    # Test zero trials
    p0, l0, u0 = wilson_interval(0, 0)
    assert p0 == 0.0 and l0 == 0.0 and u0 == 0.0
