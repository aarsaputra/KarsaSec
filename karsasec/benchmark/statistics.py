"""Statistical utility functions for Wilson score confidence intervals and benchmark metrics."""

import math


def wilson_interval(successes: int, trials: int, confidence: float = 0.95) -> tuple[float, float, float]:
    """Computes point estimate and Wilson score confidence interval (point, lower, upper).

    Args:
        successes: Number of successful outcomes (e.g. correct classifications or killed mutations).
        trials: Total number of trials / sample size.
        confidence: Confidence level (default: 0.95 for z=1.96).

    Returns:
        tuple[float, float, float]: (point_estimate, lower_bound, upper_bound).
    """
    if trials == 0:
        return (0.0, 0.0, 0.0)

    p = successes / trials
    # Z-score lookup for 95% confidence interval
    z = 1.95996 if math.isclose(confidence, 0.95) else 1.64485

    denominator = 1 + (z**2 / trials)
    centre_adjusted_probability = p + (z**2 / (2 * trials))
    adjusted_std_dev = z * math.sqrt((p * (1 - p) / trials) + (z**2 / (4 * (trials**2))))

    lower = (centre_adjusted_probability - adjusted_std_dev) / denominator
    upper = (centre_adjusted_probability + adjusted_std_dev) / denominator

    return (p, max(0.0, lower), min(1.0, upper))
