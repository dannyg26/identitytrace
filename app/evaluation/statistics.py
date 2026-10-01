"""Uncertainty on labeled workflow proportions; descriptive, not proof of validity."""

from math import sqrt


def wilson_interval(successes: int, trials: int):
    """Two-sided 95% Wilson interval, undefined when no trials were observed."""
    if not 0 <= successes <= trials:
        raise ValueError("successes must be between zero and trials")
    if trials == 0:
        return None
    z = 1.959963984540054
    p = successes / trials
    denominator = 1 + z * z / trials
    center = (p + z * z / (2 * trials)) / denominator
    half = z * sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials)) / denominator
    return {"lower": round(max(0, center - half), 4),
            "upper": round(min(1, center + half), 4), "trials": trials, "successes": successes,
            "method": "Wilson", "confidence_level": 0.95}
