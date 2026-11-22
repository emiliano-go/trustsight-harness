"""Compare a replay with the recorded document and group the misses.

A miss is only useful if it names the input it needs.  The groups below are
the input classes from the plan: a rule that missed for want of an upstream
inventory is a different problem from one that missed because the harness did
not assemble the finding set.
"""

from __future__ import annotations

from collections import Counter

from harness.lanes import lane_of

__all__ = ["GAP_GROUPS", "gap_group", "summarize"]

#: Rules whose inputs are not reconstructable from the recorded facts alone.
GAP_GROUPS: dict[str, str] = {
    "upstream": "needs an upstream inventory or the signed federation store",
    "assembly": "needs the union of findings (meta/campaign assembly), not one package",
    "longitudinal": "needs a prior-cycle snapshot or observation counter",
    "campaign": "needs campaign membership or the watchlist",
    "pure": "needs a follow-up call the pipeline makes outside the package entry",
    "other": "unclassified",
}


def gap_group(rule: str) -> str:
    if rule.startswith(("U0", "U1")) or rule in {"W014", "W015"}:
        return "upstream"
    if rule in {"H027", "M002", "M003", "H098", "H043"}:
        return "assembly"
    if rule.startswith(("H049", "H037", "H054", "T0")):
        return "longitudinal"
    if rule.startswith("G0") or rule == "W013":
        return "campaign"
    if rule in {"C016", "C023", "C033", "C034", "H023"}:
        return "pure"
    return "other"


def summarize(cases: list[dict]) -> dict:
    """Aggregate per-case rows into the replay report."""
    expected = reproduced = 0
    by_rule: Counter[str] = Counter()
    by_gap: Counter[str] = Counter()
    by_lane: Counter[str] = Counter()
    clean = 0
    unexpected: Counter[str] = Counter()
    for case in cases:
        if case.get("error") or case.get("unavailable"):
            continue
        exp = set(case.get("expected") or ())
        got = set(case.get("fired") or ())
        missed = exp - got
        expected += len(exp)
        reproduced += len(exp & got)
        if not missed and exp:
            clean += 1
        for rule in got - exp:
            unexpected[rule] += 1
        for rule in missed:
            by_rule[rule] += 1
            by_gap[gap_group(rule)] += 1
            lane = lane_of(rule)
            by_lane[lane.name if lane else "?"] += 1
    replayed = sum(1 for case in cases if not (case.get("error") or case.get("unavailable")))
    return {
        "cases": len(cases),
        "cases_replayed": replayed,
        "cases_clean": clean,
        "expected": expected,
        "reproduced": reproduced,
        "missed": expected - reproduced,
        "rate": (reproduced / expected) if expected else 0.0,
        "by_gap": dict(sorted(by_gap.items())),
        "by_lane": dict(sorted(by_lane.items())),
        "by_rule": dict(sorted(by_rule.items())),
        "unexpected": dict(sorted(unexpected.items())),
        "gap_groups": GAP_GROUPS,
    }
