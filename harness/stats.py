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
    "aligned_hole_depth",
    "bypass_rate",
    "minimum_cut_distribution",
    "minimum_layer_cut",
    "wilson_interval",
]

#: The assurance layers, outermost first (Addendum 5 §1).
_LAYER_ORDER = ("L1", "L2", "L3", "L4", "L5", "L6", "L7", "L8")


def minimum_layer_cut(paths) -> int | None:
    """The smallest layer set that intersects every attempt's path.

    *paths* is an iterable of ``{"traversed": [...], "stopped": layer|None}``
    (Addendum 5 §4).  A layer covers an attempt when the attempt stopped at
    it or traversed it.  Greedy set cover; ``None`` when there are no paths.
    """
    paths = list(paths)
    if not paths:
        return None
    uncovered = set(range(len(paths)))
    coverage = {
        layer: {
            i for i, p in enumerate(paths)
            if p.get("stopped") == layer or layer in (p.get("traversed") or ())
        }
        for layer in _LAYER_ORDER
    }
    chosen = 0
    while uncovered:
        best = max(coverage.values(), key=lambda c: len(c & uncovered), default=set())
        if not (best & uncovered):
            break
        uncovered -= best
        chosen += 1
    return chosen


def aligned_hole_depth(path) -> int:
    """The minimum set of layers whose holes had to align (Addendum 5 §4).

    ``path`` is ``{"traversed": [...], "stopped": layer|None}``.  A bypass
    (nothing stopped it) needed every layer it traversed to have a hole, so
    its depth is that count; a caught attempt needed no alignment, so 0.
    """
    if not path:
        return 0
    if path.get("stopped") is not None:
        return 0
    return len(path.get("traversed") or ())


def minimum_cut_distribution(paths) -> dict[str, int]:
    """Histogram of the per-attempt minimum cut size across a campaign.

    Each attempt is cut by one layer when it was stopped there, or by every
    layer it traversed when it bypassed (the layers whose holes aligned).
    The distribution is the campaign-level view of how many independent
    regressions a class needs.
    """
    distribution: dict[str, int] = {}
    for path in paths or ():
        if not path:
            continue
        size = 1 if path.get("stopped") is not None else len(
            path.get("traversed") or ())
        key = str(size)
        distribution[key] = distribution.get(key, 0) + 1
    return dict(sorted(distribution.items(), key=lambda kv: int(kv[0])))


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
