"""Binomial statistics for campaign records.

A bypass count on its own says nothing without the number of attempts that
produced it, and a raw fraction says nothing about how much the estimate
could move on a rerun.  The record therefore carries a Wilson interval, and
the denominator is stated rather than assumed.
"""

from __future__ import annotations

import math

# The layer-resilience primitives live in the tool under test
# (``trustsight.layers``); the harness imports them rather than keeping a
# second copy that can drift.  ``minimum_layer_cut`` is the exact cut, the
# same function the report uses.
from trustsight.layers import (  # noqa: F401
    bypass_count,
    exact_minimum_cut,
    layers_fully_bypassed,
    minimum_layer_cut,
    resilience_distribution,
    single_layer_failure,
)

__all__ = [
    "BypassRate",
    "bypass_count",
    "bypass_rate",
    "campaign_summary",
    "exact_minimum_cut",
    "layers_fully_bypassed",
    "minimum_layer_cut",
    "resilience_distribution",
    "single_layer_failure",
    "wilson_interval",
]


def campaign_summary(record: dict) -> dict:
    """The published layer-resilience numbers for a campaign record.

    Pulled out so the CLI can print them and a test can pin them without
    re-deriving the fields.
    """
    return {
        "attempts": record.get("attempts", 0),
        "outcomes": record.get("outcomes", {}),
        "bypasses": record.get("bypasses", 0),
        "minimum_layer_cut": record.get("minimum_layer_cut"),
        "single_layer_failure": record.get("single_layer_failure", {}),
        "resilience_distribution": record.get("resilience_distribution", {}),
        "layers_fully_bypassed": record.get("layers_fully_bypassed", 0),
        # Remediation T7: the attack-set limitations the numbers must be read
        # beside.
        "limitations": record.get("limitations", []),
        # Addendum 5 §6.5 M004: co-fire health notes (never a package finding).
        "cofire_health": record.get("cofire_health", []),
    }


def wilson_interval(successes: int, trials: int, z: float = 1.959963985) -> tuple[float, float]:
    """The Wilson score interval for *successes* out of *trials*.

    Wilson rather than the normal approximation because campaigns are small
    and bypass rates are near zero, which is exactly where the normal
    interval produces bounds below zero and pretends to a precision it does
    not have.
    """
    if trials <= 0:
        return (0.0, 0.0)
    p = successes / trials
    denom = 1 + z * z / trials
    centre = (p + z * z / (2 * trials)) / denom
    margin = z * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials)) / denom
    return (max(0.0, centre - margin), min(1.0, centre + margin))


class BypassRate(dict):
    """The record's `bypass_rate` object, built so it cannot omit its caveats."""


def bypass_rate(bypasses: int, reached_trustsight: int) -> BypassRate:
    """A rate over attempts that *reached TrustSight*, labelled a lower bound.

    The denominator is not the attempt count.  An attempt discarded for a
    syntax error never tested the tool, and including it would let a
    generator lower its own measured bypass rate by emitting garbage.

    The lower-bound note is part of the value rather than documentation
    around it: the behaviour validator discards chains it cannot prove, so
    the true count is at or above what this reports.
    """
    low, high = wilson_interval(bypasses, reached_trustsight)
    return BypassRate({
        # `None`, not `0.0`, when nothing reached the tool.  Zero of zero is
        # not a bypass rate: it reads as "no bypasses found" on a run that
        # measured nothing, and a campaign can reach that state with nine
        # harness errors, since the abort threshold is ten.  `None` says the
        # question was not asked, which is what happened.
        "estimate": (round(bypasses / reached_trustsight, 6)
                     if reached_trustsight else None),
        "ci_95_wilson": [round(low, 6), round(high, 6)],
        "denominator": "attempts reaching TrustSight",
        "denominator_value": reached_trustsight,
        "note": "lower bound (validator is conservative)",
    })
