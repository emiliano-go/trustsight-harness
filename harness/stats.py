"""Binomial statistics for campaign records.

A bypass count on its own says nothing without the number of attempts that
produced it, and a raw fraction says nothing about how much the estimate
could move on a rerun.  The record therefore carries a Wilson interval, and
the denominator is stated rather than assumed.
"""

from __future__ import annotations

import math

__all__ = [
    "BypassRate",
    "bypass_count",
    "bypass_rate",
    "campaign_summary",
    "minimum_layer_cut",
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
        "bypasses": record.get("bypasses", 0),
        "minimum_layer_cut": record.get("minimum_layer_cut"),
        "single_layer_failure": record.get("single_layer_failure", {}),
        # Addendum 5 §6.5 M004: co-fire health notes (never a package finding).
        "cofire_health": record.get("cofire_health", []),
    }

#: The evidence layers, ordered (Addendum 5 §1).
_LAYER_ORDER = ("L1", "L2", "L3", "L4", "L5", "L6", "L7", "L8")


def minimum_layer_cut(paths) -> int | None:
    """Exact smallest layer set that covers every caught attempt.

    *paths* is an iterable of ``{"fired": [...], "fully_bypassed": bool}``
    (Addendum 5 §4).  A layer covers an attempt when it fired for it.  The
    cut is the smallest set of layers covering every caught attempt,
    enumerated exactly over the 2**8 subsets; a fully-bypassed attempt is
    uncuttable, so any bypass makes the cut ``None`` (reported separately by
    :func:`bypass_count`).  ``None`` when there are no paths.
    """
    paths = [p for p in (paths or ()) if p]
    if not paths:
        return None
    caught = [set(p.get("fired") or ()) for p in paths]
    if any(not fired for fired in caught):
        return None
    import itertools

    for size in range(1, len(_LAYER_ORDER) + 1):
        for combo in itertools.combinations(_LAYER_ORDER, size):
            chosen = set(combo)
            if all(chosen & fired for fired in caught):
                return size
    return len(_LAYER_ORDER)


def single_layer_failure(paths) -> dict[str, int]:
    """Attempts that bypass if one layer's detector family is disabled.

    For each layer, the count of caught attempts whose *only* fired layer is
    that layer - disable it and they pass.  The empirical answer to "does one
    layer's failure reopen a path".
    """
    out: dict[str, int] = {}
    for path in paths or ():
        fired = [lit for lit in (path.get("fired") or ()) if lit]
        if len(fired) == 1:
            out[fired[0]] = out.get(fired[0], 0) + 1
    return dict(sorted(out.items()))


def bypass_count(paths) -> int:
    """Attempts that fired no rule at all."""
    return sum(1 for p in (paths or ()) if p and p.get("fully_bypassed"))


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
        "estimate": round(bypasses / reached_trustsight, 6) if reached_trustsight else 0.0,
        "ci_95_wilson": [round(low, 6), round(high, 6)],
        "denominator": "attempts reaching TrustSight",
        "denominator_value": reached_trustsight,
        "note": "lower bound (validator is conservative)",
    })
