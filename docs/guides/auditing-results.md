---
description: A campaign finished and you need to decide what it actually proved.
---

# Auditing Results

A campaign record is evidence. The harness does not tell you whether the
counts are good or bad; it tells you what happened, under what conditions, at
what cost. This page is a checklist for reading that evidence.

## 1. Check the instrument first

- `validator.calibration` must be `"passed"`. If it is not, the behaviour
  validator could not distinguish live chains from dead ones, and no bypass
  count from the build is publishable.
- `environment.canary_check` must be `"passed"`. A failed or missing canary
  means the database state was not verified.
- `environment.trustsight_version` must match the version you intended to
  measure. `"latest"` is a configuration error and the harness will not run.

## 2. Read the denominator

`bypass_rate.denominator` is "attempts reaching TrustSight". Attempts discarded
for syntax errors, constraint violations, or behaviour loss are not in the
denominator, because they never tested the tool. A generator that emits a lot
of garbage can make its own rate look better or worse depending on where the
garbage lands; the denominator makes that visible.

## 3. Treat bypass as a lower bound

`bypass_rate.note` says "lower bound (validator is conservative)". This is not
a disclaimer; it is a structural property. The validator discards chains it
cannot prove, so the true bypass count is at or above the reported count.

## 4. Inspect partial evasions and fail-closed catches

- `partial_evasion` means TrustSight flagged the diff, but not with the rule the
  campaign was testing. It is a granularity result, not a tool-level bypass.
- `fail_closed_catch` means a coverage gap forbade UNFLAGGED. The tool declined
  to answer. These are positive results for TrustSight's fail-closed design,
  and they are exported as regression tests for that layer.

## 5. Review exported fixtures before merging

The harness exports bypasses to `fixtures-out/` for human review. A fixture
includes the diff, the trace, and an `expected.json` with `must_fire: []` left
for the reviewer to assign. The harness never opens a pull request.
