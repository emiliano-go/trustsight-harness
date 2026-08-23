---
description: Deterministic versus stochastic campaigns, lower-bound reporting, and what a record can claim.
---

# Measurement and Maturity

The harness turns a claim into evidence. A claim like "an LLM found N bypasses"
is meaningless without stating the instrument, the environment, and the
population of attempts. This page describes the discipline the record enforces.

## Deterministic campaigns

A manual campaign with committed inputs is deterministic in the generator
sense: replay produces the same diff hashes. Whether the verdicts are
reproducible depends on the pinned (TrustSight version, environment) pair.

If the campaign declares `environment.accumulate: true`, verdicts become
order-dependent even with deterministic inputs, because the database warms as
the campaign runs. Such a campaign is classified as stochastic.

## Stochastic campaigns

LLM and mutation campaigns produce different diffs on different runs. Their
results are reported as binomial proportions with Wilson intervals, not as
reproducible counts. Compare them only under the same (TrustSight version,
environment, prompt hash) triple.

## Lower-bound reporting

The behaviour validator is conservative: a false negative discards one attempt;
a false positive certifies a dead payload. Because false positives are worse,
the validator refuses when uncertain. Therefore every bypass count is a lower
bound. The record states this explicitly in `bypass_rate.note`.

## What a record cannot claim

A campaign record is valid only for itself. It cannot say:

- "TrustSight is robust" — only "this generator, this version, this many
  attempts, found N proven bypasses."
- "Version A is better than version B" — that is the regression gate's job,
  expressed as open/closed bypasses.
- "The true bypass rate is exactly X" — the Wilson interval gives a range, and
  the lower-bound note says the true count may be higher.

These limits are not accidents; they are enforced by the schema and by the
Judge.
