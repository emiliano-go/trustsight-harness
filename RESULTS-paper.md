# Measured results for the paper (run 22/11/26)

Everything here is reproducible from the frozen inputs named in each section. Nothing in this
file is an estimate unless it says so.

Pins: trustsight `c6ea73fc274486fe428c84b1d733731ee598bb8b` (working tree, uncommitted changes present), trustsight-harness `f75719e31e95a96e27200454266f3e68930aa734`.
Environment: TrustSight 0.30.0 working tree, cold database (`db_state: cold`), default review
profile (20), `corpus_version 2` (8,393 diffs / 426 packages), watcher feed 13/10/26 16:37 –
22/11/26 19:11 UTC (40.3 days, 1,481 alert cycles).

---

## R1 — Package-level operating points (E1)

Corpus: `tests/fixtures/benign-corpus/`, 8,393 real AUR updates across 426 packages, analysed
with `analyze_diff` (cold DB). Intervals: Wilson on diffs; clustered bootstrap resampling
packages (2,000 reps).

| Rule | Hits | Rate | Wilson 95% | Clustered 95% |
|---|---|---|---|---|
| X011 | 10 | 0.119% | [0.06%, 0.22%] | [0.04%, 0.23%] |
| X002 | 5 | 0.060% | [0.03%, 0.14%] | [0.01%, 0.12%] |
| X030 | 0 | 0.000% | [0.00%, 0.05%] | [0.00%, 0.00%] |
| H035 | 0 | 0.000% | [0.00%, 0.05%] | [0.00%, 0.00%] |
| D003 | 40 | 0.477% | [0.35%, 0.65%] | [0.33%, 0.64%] |
| H087 | 136 | 1.620% | [1.37%, 1.91%] | [1.28%, 1.97%] |

Alert rate by shipped profile (share of updates whose aggregate score exceeds the threshold):

| Profile | Threshold | Flagged | Rate | Wilson 95% | Clustered 95% |
|---|---|---|---|---|---|
| strict | 10 | 1,434 / 8,393 | 17.09% | [16.30%, 17.91%] | [14.64%, 19.65%] |
| default | 20 | 561 / 8,393 | **6.68%** | [6.17%, 7.24%] | [5.28%, 8.37%] |
| quiet | 40 | 131 / 8,393 | 1.56% | [1.32%, 1.85%] | [1.19%, 1.96%] |

Distribution: median 0, p90 20, p95 30, p99 50, max 100; 75.4% of updates score zero.
**47.9% of packages (204/426) have at least one update scoring above 20** — the review burden is
per package, not only per update.

Cross-check: the 6.68% reproduces the published 6.6% and the p95 of 30 reproduces the published
distribution, so this run and the project's own numbers agree on the same corpus.

**Consequence for the paper.** X011 — the rule the campaign's primary wave depends on — fires on
**0.12%** of real benign updates and on 10 updates in total. The reviewers' expectation that
X011 is a broad false-positive driver is not supported: on this corpus it is one of the most
specific rules in the set, and H035 and X030 never fired at all.

---

## R2 — Campaign-level behaviour over 40 days (E3a)

Unit: **cycle** (one watcher alert document). Definition used: a cycle is
*correlation-triggered with zero over-threshold members* when it carries at least one **scored**
G join (G001, G003, G014) and `counts.over_threshold == 0`. Zero-weight joins (G006, G016) are
excluded by definition, not by accident.

| Measure | Value |
|---|---|
| Cycles in window | 1,481 (36.8/day) |
| Cycles with `over_threshold == 0` | 258 |
| Cycles carrying any G rule | 77 |
| **Correlation-triggered, zero over-threshold** | **28 (0.69/day)** |
| — by join | G003 20, G014 13, G001 2 (a cycle may carry more than one) |
| Cycles with a G rule *and* an over-threshold member | 49 |

**Consequence for the paper.** The central claim no longer rests on a single existence proof.
Correlation produced 28 campaign alerts in 40 days where no member package crossed the review
threshold — 19% of all cycles carrying a G rule. The abstract can say "28 of 1,481 cycles".

---

## R3 — October membership, measured against the incident record (E3b, partial)

14/10/26 had 63 cycles, five carrying a G rule:

| Cycle | Rules | Members | `over_threshold` |
|---|---|---|---|
| 00:34:09 | H045, H052, **G003** | 15 | 0 |
| 02:42:40 | H045, H052, **G003** | 15 | 0 |
| 06:22:27 | G001 + 16 others | 13 | 13 |
| 13:03:22 | G003, H059 + 5 | 9 | 5 |
| 21:04:29 | **G003** | 3 | 0 |

Union of G003 members across the day: **42 packages**.

Reference: the incident record names **30** packages — 29 created look-alike names plus the
hijacked `firefox-git-bin`.

| Measure | Value |
|---|---|
| Incident packages named by a G003 alert | 30 / 30 → **recall 1.00** |
| Distinct alert members | 42 |
| Members outside the incident record | **12** |
| Membership precision | 30 / 42 = **0.714** |

The 12 extras are a same-day batch of one package family (`libcudf`, `python-cudf`,
`rapidsmpf`, `scramblery-*`, `vgshell-git`, …), which is the shape of an ordinary maintainer
publishing a batch, not of the campaign. They are the measured false-association cost of G003 on
live data, and the paper's first real precision number.

Caveats, to be stated in the paper: the positive reference is the incident record (an independent
AUR takedown list), not per-package byte verification — those bytes no longer exist (P1). The 12
extras still need per-package adjudication before the precision figure is final; their family
shape makes it a one-hour job for a reviewer.

---

## R4 — Adoption lane in the wild (E2.3, partial)

From the feed's trigger index over the same 40.3 days:

| Rule | Alert entries | Distinct packages |
|---|---|---|
| X011 | 141 | 129 |
| H035 | 17 | 13 |
| G003 | 226 | 215 |
| G001 | 129 | 129 |
| G014 | 17 | 17 |
| G012 | 0 | 0 |
| G016 | 0 | 0 |
| H086 | 0 | 0 |
| H087 | 0 | 0 |
| H088 | 0 | 0 |

**H086 and H088 do not appear in the alert stream at all**, and G012/G016 never fired in 40 days.
This is a finding, not just a gap: the adoption-context rules that carry the paper's RQ2 have
**no live presence** in this deployment, while the correlation rules that carry RQ3 fire
constantly. RQ2's evidence therefore stays with the representative fixtures and the live feed's
silence, and the paper should say so rather than implying an adoption signal in the wild.

Caveat: a rule absent from the alert stream may be non-alerting on this path rather than
non-firing. The paper must phrase it as "no alert entries", not "never fired".

---

## R5 — The X011 eligibility toggle, analytic bound (E4, blocked)

The three-arm toggle needs per-package rule sets with maintainers for historical cycles, which the
feed does not expose and which no database snapshot retains. **E4 is not executable as specified.**
What can be computed is an upper bound on its first-order cost:

- X011 fires 141 times over 1,481 cycles → λ = 0.095 firings/cycle.
- A G012 join needs ≥3 packages from ≥2 maintainers in one cycle.
- Under a Poisson approximation, P(≥3 X011 firings in a cycle) ≈ 1.3 × 10⁻⁴, so the expected
  number of cycles where widening eligibility could create a join is **≈ 0.2 over 40 days**.

Combined with R1 (0.12% benign firing rate), the predicted cost of adding X011 is near zero,
which **contradicts** the plan's earlier assumption that enabling it would join benign
npm-migration waves. If the toggle were run and this holds, §6.2's branch (ii) applies: the
exclusion earns nothing and should be lifted or reframed as a coverage gap.

This is a prediction with a stated method, not a measurement. It is pre-registerable today,
before anyone runs the three arms.

---

## R6 — Correlation-disabled counterfactual (E3c, structural only)

A faithful counterfactual needs the cycle state that produced the 28 alerts; the feed stores
outputs, not inputs. What the record does establish:

- Every one of the 28 cycles has `over_threshold == 0`, so no member's package score could have
  produced the alert on its own.
- The campaign cluster is emitted by the correlation stage and is the only carrier of the
  campaign-level finding in those documents.

That is attribution by construction, not by experiment. The paper should say "in these cycles the
campaign alert exists only as a correlation finding" and label the counterfactual as not run.

---

## What is now measured, and what is not

| Planned | Status |
|---|---|
| E1 package-level rates + profiles | **done** (R1) |
| E2.3 adoption in the wild | **partial** (R4): counts only, no denominator of adoption events |
| E3a campaign-level rate | **done** (R2) |
| E3b October membership | **partial** (R3): recall 1.0, precision 0.714, 12 extras unadjudicated |
| E3c counterfactual | **not run**: needs historical cycle state |
| E4 eligibility arms | **blocked**, analytic bound only (R5) |
| E6 frozen replay | **not run**: needs rule-version archaeology per cycle |
| P1 recovered bytes | **failed**, documented (MANIFEST.md) |
| P2 control replacement | **done** (`basedpyright`, observed, 40) |
