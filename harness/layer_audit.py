"""Section 6: classify a bypass by the layers that never got a shot.

A bypass on which every assurance layer was exercised and none fired is a
*ruleset* hole: the instrument looked everywhere and saw nothing.  A bypass on
which a layer never ran - a cold observation database, a disabled build lane -
is a *configuration* hole: the instrument was blind, not wrong.  Confusing the
two sends effort to the wrong place.

Two laws hold this module together.

**Classification, never verdict.**  The status taxonomy stays binary: a
``bypass`` keeps its verbatim definition (syntax valid, constraints honoured,
behaviour proven, UNFLAGGED).  ``FULL-N`` is metadata on the bypass, not a new
status; a "partial bypass" verdict would be quoted as "the tool half-caught
it", which is false.

**Observed status, never inferred traversal.**  Every field is a projection of
the report's own ``layers`` object plus the run's recorded configuration.  It
never reconstructs "how far an attacker got" from a path shape - core retired
that model because inferred traversal made every path structurally contain L1
and the minimum cut trivially one.
"""

from __future__ import annotations

__all__ = [
    "CONDITIONAL_REASONS",
    "LAYERS",
    "REASONS",
    "VERIFY_LAYER",
    "audit",
    "is_conditional",
    "reason_summary",
]

#: The eight evidence categories, in order.  The optional build lane (L9) is
#: not one of them and is tracked separately.
LAYERS: tuple[str, ...] = ("L1", "L2", "L3", "L4", "L5", "L6", "L7", "L8")
VERIFY_LAYER = "L9"

#: Why a layer was not exercised.  A closed set, the same discipline as the
#: coverage-gap vocabulary: an unknown reason is a programming error, not a
#: value to pass through.
#:
#: - ``cold_state``  the layer needs input the run's database does not hold.
#: - ``lane_disabled`` the optional L9 build lane is off or unavailable.
#: - ``shape_inapplicable`` the attempt produces no evidence of this category.
#: - ``config``      a ``[layers]`` override or suppression removed the sensor.
REASONS = frozenset({"cold_state", "lane_disabled", "shape_inapplicable", "config"})

#: Reasons that make a bypass *conditional*.  ``shape_inapplicable`` never
#: does: a layer with no evidence to read is not a blind sensor.
CONDITIONAL_REASONS = frozenset({"cold_state", "lane_disabled", "config"})

#: Layers whose evidence is stored observation history.
_HISTORY_LAYERS = frozenset({"L6"})
#: Layers whose evidence is signed external data (the IOC baseline).
_INDICATOR_LAYERS = frozenset({"L7"})
#: Layers whose evidence is the collective, cross-package pass.
_CORRELATION_LAYERS = frozenset({"L8"})

#: ``db_state`` values that mean the database already holds observations.
_WARM_DB_STATES = frozenset({"seeded", "snapshot"})


def audit(
    layers,
    *,
    db_state: str = "cold",
    accumulate: bool = False,
    ioc_baseline: bool = False,
    verify_lane: bool = False,
    suppressed_layers=(),
    empty_layers=(),
):
    """Project one attempt's layer audit from its report and the run config.

    *layers* is the report's own ``layers`` object (``{L1: {detection,
    coverage, ...}, ...}``).  The rest are the run's recorded configuration:
    the database state, whether observations accumulate, whether an IOC
    baseline was imported, whether the L9 lane ran, and any layers a
    ``[layers]`` override or suppression removed.  No path, and no attempt
    text, is consulted - the audit cannot infer a traversal it was not given.
    """
    layers = layers or {}
    removed = {str(layer) for layer in suppressed_layers}
    removed.update(str(layer) for layer in empty_layers)
    warm = bool(accumulate) or str(db_state) in _WARM_DB_STATES
    has_ioc = bool(ioc_baseline)

    exercised: list[str] = []
    not_exercised: dict[str, str] = {}

    for layer in LAYERS:
        info = layers.get(layer) or {}
        fired = str(info.get("detection", "none")) == "fired"
        coverage = str(info.get("coverage", "complete"))

        if fired:
            # A finding proves the layer ran, whatever the config says.
            exercised.append(layer)
            continue
        if layer in removed:
            not_exercised[layer] = "config"
            continue
        if layer in _HISTORY_LAYERS and not warm:
            not_exercised[layer] = "cold_state"
            continue
        if layer in _INDICATOR_LAYERS and not has_ioc:
            not_exercised[layer] = "cold_state"
            continue
        if layer in _CORRELATION_LAYERS and coverage == "not_applicable":
            not_exercised[layer] = "cold_state"
            continue
        if coverage == "not_applicable":
            not_exercised[layer] = "shape_inapplicable"
            continue
        exercised.append(layer)

    if verify_lane:
        exercised.append(VERIFY_LAYER)
    else:
        # The harness has no L9 build lane: a bypass measured here never
        # exercised artifact reality, so it cannot claim a FULL result.
        not_exercised[VERIFY_LAYER] = "lane_disabled"

    conditional = {
        layer: reason
        for layer, reason in not_exercised.items()
        if reason in CONDITIONAL_REASONS
    }
    return {
        "exercised": exercised,
        "not_exercised": not_exercised,
        "classification": "conditional" if conditional else "full",
        "conditional_count": len(conditional),
        "conditional_reasons": conditional,
    }


def is_conditional(audit_record) -> bool:
    """True when *audit_record* classifies the bypass conditional (FULL-N)."""
    return bool(audit_record) and audit_record.get("classification") == "conditional"


def reason_summary(audits) -> dict[str, int]:
    """Per-reason counts over bypass audits, for the record summary.

    A bypass counts once per distinct reason it carries, so the map reads
    "this many bypasses were blind for this reason", the remediation map the
    specification asks for beside the headline bypass count.
    """
    counts: dict[str, int] = {}
    for record in audits or ():
        for reason in set((record or {}).get("conditional_reasons", {}).values()):
            counts[reason] = counts.get(reason, 0) + 1
    return dict(sorted(counts.items()))
