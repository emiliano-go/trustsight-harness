"""Section 2: the minimal repro.

A raw LLM bypass is bloated - the model pads a working diff with churn - and
the pad is not evidence.  The smallest diff that still (a) parses, (b) honors
the campaign's constraints, (c) keeps the attack chain proven, and (d)
bypasses the same rule by the same shape is the one a human reviews and a
pattern author patches against.

The shrink is delta debugging over the diff's change lines.  The oracle is
the pipeline itself, so minimization reuses shipped machinery and cannot
certify a repro the pipeline would reject.  It runs *after* the verdict, so
its cost never contaminates the attempt's measurement record - the metric is
coverage, and minimization is bookkeeping.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

__all__ = ["MinimizeResult", "change_line_indices", "ddmin", "minimize"]

#: A candidate's oracle: ``True`` when the pipeline still accepts it.
Oracle = Callable[[str], bool]

#: Above this many change lines the diff is not a repro to shrink but a file
#: to look at; ddmin is skipped so a hostile diff cannot turn bookkeeping into
#: an O(units x budget) scan.  The sanitizer already caps diff bytes, so this
#: is a second, cheaper ceiling on the work.
MAX_CHANGE_UNITS = 4096


@dataclass(frozen=True)
class MinimizeResult:
    """The smallest repro found, and what it cost to find it."""

    diff: str
    change_lines: int
    original_change_lines: int
    #: Oracle calls spent.  Never added to the attempt's analysis count: the
    #: measurement is of the generator, and minimization is bookkeeping.
    analyses: int
    #: The budget ran out before a fixpoint; the best-so-far reduction is kept.
    partial: bool


def change_line_indices(lines: list[str]) -> list[int]:
    """Indices of the diff's change lines: added or removed content.

    File headers (`---`/`+++`), hunk headers (`@@`), context lines and the
    `\\ No newline` marker are structure, never removable.  Removing an
    added line without its matching hunk count is safe here because the
    syntax validator's own `parse_unified_diff` reconstructs from the lines
    and does not read the counts - the oracle is the whole check either way.
    """
    return [
        index for index, line in enumerate(lines)
        if line[:1] in ("+", "-")
        and not line.startswith(("+++", "---"))
    ]


def _rebuild(lines: list[str], changes: list[int], keep: frozenset[int]) -> str:
    """*lines* with the change line at *index* dropped unless in *keep*."""
    dropped = set(changes) - set(keep)
    return "\n".join(line for index, line in enumerate(lines) if index not in dropped)


def ddmin(units: list[int], test: Callable[[frozenset[int]], bool],
          budget: int) -> tuple[list[int], int, bool]:
    """Zeller's ddmin over *units*, counting oracle calls against *budget*.

    *test* is given the units to *keep* and answers whether that complement
    still holds every property.  Returns ``(kept, calls, partial)``.  The
    algorithm halves, then quarters, and grows the granularity when a pass
    finds nothing - the standard 1-minimal search, bounded so attacker-grade
    input cannot spend unbounded analyses.
    """
    current = list(units)
    calls = 0
    granularity = 2
    partial = False
    while len(current) >= 2:
        chunk = -(-len(current) // granularity)  # ceil
        reduced = False
        for start in range(0, len(current), chunk):
            if calls >= budget:
                partial = True
                break
            victim = current[start:start + chunk]
            complement = frozenset(u for u in current if u not in victim)
            calls += 1
            if test(complement):
                current = [u for u in current if u not in victim]
                granularity = max(2, granularity - 1)
                reduced = True
                break
        if partial:
            break
        if not reduced:
            if granularity >= len(current):
                break
            granularity = min(granularity * 2, len(current))
    return current, calls, partial


def minimize(diff_text: str, test: Oracle, *, budget: int = 24) -> MinimizeResult:
    """Shrink *diff_text* to the smallest change set the oracle still accepts.

    *test* must re-run the whole pipeline on a candidate - parse it, honor
    the constraints, prove the chain, and land `bypass` with the same
    `(rule, shape)`.  The minimizer only ever drops change lines, so it
    cannot introduce a shape the original did not have; a reduction that
    changed the shape is refused by *test*, not by a second check here.

    Budget is the count of oracle calls, so a campaign's declared
    `minimize_budget` bounds the extra analyses exactly.
    """
    lines = diff_text.split("\n")
    changes = change_line_indices(lines)
    if len(changes) < 2:
        return MinimizeResult(diff_text, len(changes), len(changes), 0, False)
    if len(changes) > MAX_CHANGE_UNITS:
        # Too large to shrink safely; keep the original and mark it, rather
        # than spend the budget on a scan the result would not justify.
        return MinimizeResult(diff_text, len(changes), len(changes), 0, True)

    kept, calls, partial = ddmin(
        changes, lambda keep: test(_rebuild(lines, changes, keep)), budget)
    return MinimizeResult(_rebuild(lines, changes, frozenset(kept)),
                          len(kept), len(changes), calls, partial)
