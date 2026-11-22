---
description: The nine analysis lanes, the entry point each one owns, and how every rule in the alert space is either reproduced or excluded with evidence.
---

# Lanes

A **lane** is the entry point a rule needs to fire. It is not a category and
not a severity: two rules in the same documentation section can live in
different lanes because TrustSight reaches them through different functions.

`harness/lanes.py` assigns every contract rule to exactly one primary lane and
a test fails if any rule is unassigned or assigned twice. The lane counts are
pinned, so a rule added upstream lands as a deliberate choice rather than
silently in `static`.

| Lane | Entry point | Rules |
|---|---|---|
| `static` | `analysis.pipeline.scan_diff` / `analyze_package` | 217 |
| `artifact` | `analysis.artifact.inspect_manifest` | 11 |
| `upstream` | `release_asset.compare_release_asset`, `upstream_release.upstream_release_findings`, `upstream_collect` | 9 |
| `warm` | the text pipeline over a **seeded** observation ledger | 3 |
| `project` | the git acquisition path (tree plus AUR timestamps) | 5 |
| `cycle` | `temporal_engine.run_corpus_sweep`, `graph.run_graph_sweep`, `longitudinal_findings`, `adoption_findings` | 27 |
| `compose` | rule functions over pipeline state (a finding list, a text, bytes) | 19 |
| `correlation` | `correlation.correlate` and the adoption/watchlist/campaign passes | 16 |
| `meta` | `meta.m_series_findings` and the tool-health passes | 7 |

## Lane probes

`campaign_type: lane-probe` runs committed payloads through a lane's entry
point. A payload is data, never a re-implementation of the rule: a cycle cell
is a metadata snapshot, a compose cell is the state the pipeline would have
held, a warm cell seeds a ledger key or domain before the rule runs.

```yaml
campaign: lane-cycle
campaign_type: lane-probe
generator:
  type: lane
  manifest: inputs.yml
```

Each cell names its lane, its payload and the rules it expects:

```yaml
- id: H047-positive
  lane: cycle
  payload_path: fixtures/lane/cycle/longitudinal-h047.json
  expect_fire:
  - H047
```

The record carries a `flag_ledger` row per cell: the expected rules, the rules
that actually fired, the score, and whether the report would be flagged. A
cell whose rule does not fire is recorded as a probe miss, not as a bypass.

## The compose lane, and why it exists

Several rules are emitted by pure functions that the pipeline calls with
intermediate state a diff never carries: a finding list, a recipe text, an
owned-namespace configuration, archive bytes. A tenth *analysis* entry point
per rule would be noise; `compose` instead makes the missing input explicit.
The fixture is the state the pipeline would have held, and the rule's own
function still does the work.

This is also where the honest limit shows up. `compose` cannot invent a git
tree, a signed manifest or an upstream scan. Rules that need those are listed
in `alerts/exclusions.json` with the emitter, the reason and the evidence, and
two tests keep that list honest: every unreproduced rule must have an entry,
and an entry must be deleted the moment its rule fires.

## The project lane's limitation

H020-H022, T006 and T007 read a `project` object with `commit_meta` and
`walk`. The lane supplies a **git-shaped fixture** — commits by id plus a walk
from a head — and a fixed clock from the payload, which keeps the age rules
deterministic forever.

That exercises the rule logic. It does **not** exercise real git acquisition,
so a defect in the checkout or timestamp plumbing would not be caught here.
The acquisition path has its own coverage in TrustSight's tests.

## Mutation checks

A rule that fires only when a line is spelled one particular way is weaker
than one that fires on the technique. `scripts/check_lane_mutations.py`
re-analyses committed probe diffs after surface-only changes — trailing
whitespace, a harmless comment line, a blank line — and reports any rule that
stops firing.

```console
$ uv run python scripts/check_lane_mutations.py --limit 120 --fail-on-regression
REGRESSION rule-probes-h/H069-positive under trailing-space: ['H069']
checked 353 mutated analyses over 120 cases; 2 regression(s)
```

The two known regressions live in `mutations/baseline.json`. CI fails on a
**new** regression and on a baseline entry that no longer reproduces, so the
ledger shrinks as upstream rules are fixed instead of accumulating.

## Reading the ledger

```console
$ harness coverage
326 of 326 rules targeted by 129 campaigns; 291 have a firing probe, ...

$ harness outcomes
# per-rule lane, fixtures, fired cells, last firing version

$ harness watcher_replay
# every captured watcher alert, rule by rule
```

`harness/watcher.py` replays the committed alert catalog in
`watcher/alerts/`: each recorded alert's rules are matched against the firing
ledger. Pseudo ids (`COVERAGE`, `NOVELTY`, `SOURCE_BUCKET`) and the P-series
declarations (P001-P009) are counted separately — they render the report, they
are not detections.
