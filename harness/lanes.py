"""Which analysis lane can fire each rule.

A rule is not reachable everywhere.  The static lane reads one recipe, cold;
the artifact lane reads a built-package manifest; the warm lane reads a seeded
observation history; the project lane needs a git tree and AUR metadata; the
cycle lane needs one metadata cycle; correlation needs the cycle's records;
meta needs a finding set; upstream needs an inventory or a workflow.

This module is the one assignment.  It is deliberately explicit rather than
derived from a category or a series: two rules in the same category can need
different state, and a wrong guess here is a rule the harness claims to
measure and never does.  The totality gate in ``tests/test_lanes.py`` fails
when a contract id has no lane or two.
"""

from __future__ import annotations

from dataclasses import dataclass

from trustsight.contract import rule_ids

__all__ = [
    "LANES",
    "UNREACHABLE",
    "Lane",
    "lane_of",
    "rules_by_lane",
]


@dataclass(frozen=True, slots=True)
class Lane:
    """One kind of state a rule's emitter needs, and the rules that need it."""

    name: str
    rules: frozenset[str]
    entry: str
    reason: str


#: The A-series manifest inspector: the built package, not the recipe.
_ARTIFACT = frozenset({
    "A001", "A002", "A003", "A004", "A005", "A006", "A007", "A008",
    "A011", "A012", "A013",
})

#: Upstream inventories, release assets and CI workflows.
_UPSTREAM = frozenset({
    "A009", "A010", "A014", "A015", "A016",
    "U007", "U008", "U013", "U014",
})

#: Ledgers the text pipeline reads: signing keys, maintainer domains.
_WARM = frozenset({"T001", "T002", "T003"})

#: The git acquisition path: a tree plus AUR metadata timestamps.
_PROJECT = frozenset({"H020", "H021", "H022", "T006", "T007"})

#: One metadata cycle: newer/older metadata, history and graph inputs.
_CYCLE = frozenset({
    "H026", "H028", "H037", "H044", "H045", "H046", "H049", "H050",
    "H051", "H052", "H053", "H054", "H055", "H057", "H058", "H060", "H061",
    "H073", "H074", "H086", "H087", "H088",
    "T008", "T009", "T010", "T011", "T012",
})

#: Rule functions the pipeline wires over intermediate state: a finding set,
#: a recipe text, archive bytes.  The lane supplies that state as a fixture.
_COMPOSE = frozenset({
    "C035", "H029", "H070", "H098", "H102", "H104", "H105", "H107",
})

#: The cross-package pass over cycle records.
_CORRELATION = frozenset(f"G{n:03d}" for n in range(1, 17))

#: A finding set plus the declared claims it is read against.
_META = frozenset({"H043", "M001", "M002", "M003", "M004", "M005", "M006"})


def _build() -> dict[str, Lane]:
    assigned: set[str] = set()
    rows: dict[str, Lane] = {}
    for lane in (
        Lane("artifact", _ARTIFACT, "analysis.artifact.inspect_manifest",
             "reads the built package manifest, not the recipe"),
        Lane("upstream", _UPSTREAM,
             "analysis.release_asset.compare_release_asset / "
             "analysis.upstream_release.upstream_release_findings",
             "reads an upstream inventory, asset or workflow"),
        Lane("warm", _WARM,
             "analysis.pipeline._core.scan_recipe with a seeded database",
             "reads an observation ledger the cold text lane does not have"),
        Lane("project", _PROJECT, "analysis.pipeline._analyze.analyze_package",
             "needs a git tree and AUR metadata timestamps"),
        Lane("cycle", _CYCLE,
             "full_aur.temporal_engine.run_corpus_sweep",
             "needs one metadata cycle and the history around it"),
        Lane("compose", _COMPOSE,
             "analysis rule functions over fixture state (findings, text, bytes)",
             "supplies the intermediate state the pipeline normally holds"),
        Lane("correlation", _CORRELATION, "analysis.correlation.correlate",
             "joins records across packages in a cycle"),
        Lane("meta", _META, "analysis.meta.m_series_findings",
             "reads a finding set rather than a recipe"),
    ):
        overlap = assigned & set(lane.rules)
        if overlap:
            raise RuntimeError(f"rules assigned twice: {sorted(overlap)}")
        assigned |= set(lane.rules)
        rows[lane.name] = lane
    known = set(rule_ids())
    unknown = assigned - known
    if unknown:
        raise RuntimeError(f"lane names a rule that does not exist: {sorted(unknown)}")
    rows["static"] = Lane(
        "static", frozenset(known - assigned),
        "analysis.pipeline.scan_diff",
        "reads one recipe with a cold database",
    )
    return rows


LANES: dict[str, Lane] = _build()


def lane_of(rule_id: str) -> Lane | None:
    """The lane that owns *rule_id*, or ``None`` for a pseudo id."""
    for lane in LANES.values():
        if rule_id in lane.rules:
            return lane
    return None


def rules_by_lane() -> dict[str, tuple[str, ...]]:
    """Every lane's rules, sorted, in the closed lane order."""
    order = ("static", "artifact", "upstream", "warm", "project",
             "cycle", "compose", "correlation", "meta")
    return {name: tuple(sorted(LANES[name].rules)) for name in order}


#: Rules a cold static campaign cannot fire, with the lane that can.
#: Kept here so the coverage report says *why* a rule is outside the static
#: lane instead of only that it is.
UNREACHABLE: dict[str, str] = {
    rule: f"needs the {lane.name} lane: {lane.reason}"
    for lane in LANES.values() if lane.name != "static"
    for rule in lane.rules
}
