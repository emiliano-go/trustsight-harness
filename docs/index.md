---
description: "Full documentation for trustsight-harness: reproducible, cost-tracked adversarial measurement against a pinned TrustSight build."
---

# trustsight-harness

Turns "an LLM found N bypasses" into a reproducible, auditable, cost-tracked
measurement against a pinned [TrustSight](https://docs.trustsight.org/) build.

The harness is an **instrument, not a judge**; the same rule the tool it
measures applies to itself. A campaign produces diffs, traces, verdicts and
costs. Whether those numbers are good news is a maintainer's decision, made in
public with the record attached. The [self-security model](security.md) states
the boundaries the harness holds itself to, and how each one is enforced.

Ready to run one? Start with [Getting Started](getting-started/index.md).

---

## What it measures

A **bypass** is one thing and nothing else: a diff whose syntax is valid, whose
declared constraints were honoured, whose attack chain is provably intact, and
which TrustSight returned **UNFLAGGED** for; score at or below the threshold,
no coverage gaps, no FATAL finding.

Everything else has its own name, and the names matter:

| Result | What happened | Counts as a bypass? |
|---|---|---|
| `detected` | A FATAL fired, or the score went above the threshold with an expected rule firing | No |
| `partial_evasion` | The expected rule stayed quiet, but something else caught it | No; the catching rules are named |
| `fail_closed_catch` | A coverage gap forbade UNFLAGGED: the tool declined to answer | **No; the design working** |
| `bypass` | UNFLAGGED, with syntax, constraints and behaviour all proven | Yes |

Pushing a payload past a read bound does not produce a clean result in
TrustSight; it produces an incomplete one. Counting that as a bypass would
score the tool worst exactly where it behaves best. The full table is in
[Terminal Statuses](reference/statuses.md).

## Every published count is a lower bound

The behaviour validator is conservative on purpose. Discarding a live payload
costs one attempt; certifying a dead one puts a fabricated bypass into a record
other people will cite. So it refuses whenever it cannot prove the chain, and
the true bypass count is at or above whatever any record reports. The record
says so in the field itself, next to the number.

!!! warning "The phrase to avoid"

    "TrustSight was bypassed N times" is only ever shorthand for "N bypasses
    were **proven**". See [Measurement and Maturity](explanation/measurement-and-maturity.md).

## Reproducibility is the whole design

TrustSight's score is a function of the diff, the config, **and the observation
history it accumulates**; and every analysis writes to that history. A harness
that pins the first two and lets the third drift is measuring its own run order.

So each attempt runs against a restored database, verified by a canary whose
score is committed, with the config fingerprint re-checked on every attempt
rather than once at startup. `trustsight_version: "latest"` is a configuration
error, not a convenience.

---

## Getting started

| Page | What it covers |
|------|----------------|
| [Installation](getting-started/installation.md) | Install with `uv`, pointed at the TrustSight build you mean to measure. |
| [Quickstart](getting-started/quickstart.md) | Run the shipped campaign and read the summary in under five minutes. |
| [Running a Campaign](getting-started/running-a-campaign.md) | Run the shipped campaign, read the summary, find the traces. |
| [Reading a Record](getting-started/reading-a-record.md) | Every field of `record.json`, and what each one is evidence for. |

## Guides

| Guide | When to read it |
|-------|-----------------|
| [Writing a Campaign](guides/writing-a-campaign.md) | You want to measure something the shipped campaigns do not cover. |
| [Using in CI](guides/using-in-ci.md) | Gate pull requests on the regression gate or a campaign record. |
| [Auditing Results](guides/auditing-results.md) | A campaign finished and you need to decide what it actually proved. |

## Reference

| Page | What it covers |
|------|----------------|
| [CLI](reference/cli.md) | `python -m harness <campaign>` and `python -m harness regression`. |
| [Campaign Configuration](reference/campaign-config.md) | Every key of `campaign.yml`, and which ones refuse to be omitted. |
| [Record Schema](reference/record-schema.md) | `record.json`, field by field, including the forbidden fields. |
| [Terminal Statuses](reference/statuses.md) | The Section 1.3 matrix, in the order the Judge applies it. |
| [Exit Codes](reference/exit-codes.md) | 0, 1, 2; and why "bypasses found" is not among them. |

## Explanation

| Page | What it covers |
|------|----------------|
| [Measurement and Maturity](explanation/measurement-and-maturity.md) | Deterministic versus stochastic campaigns, lower bounds, and what a record can claim. |
| [What the Harness Cannot Prove](explanation/what-the-harness-cannot-prove.md) | The reasoned ceiling of the instrument. |
| [Design Notes](explanation/design-notes.md) | Where the specification was open, and where reality contradicted it. |

## Contributing

| Page | What it covers |
|------|----------------|
| [Development Setup](contributing/development-setup.md) | Lockfile-only installs, the test suite, the gates. |
| [Acceptance Criteria](contributing/acceptance-criteria.md) | Section 11, with the test that checks each item. |
| [Reviewing a Security Control](contributing/security-review.md) | What to look at when a gate or a boundary changes. |
| [Releasing](contributing/releasing.md) | Tags, SBOM, and the llms.txt companions. |

---

[Self-Security Model](security.md) &middot; [License](license.md)
