---
description: The eleven terminal statuses an attempt can end in, and the order the Judge applies them in.
---

# Terminal Statuses

Every attempt ends in exactly one status. The set is closed: `harness/status.py`
is the single definition that the Judge, the Recorder and the Exporter all read,
so a status cannot exist in one and not the others.

## The matrix

| Status | Meaning | Counts as a bypass? |
|---|---|---|
| `sanitization_failure` | Rejected before validation: null byte, path escaping the tree, over the size cap | No |
| `duplicate` | Hash already seen in this campaign, or already recorded as a bypass at this same version | No |
| `syntax_error` | Not a well-formed unified diff, or `bash -n` rejected the old or new PKGBUILD | No |
| `constraint_violation` | The output used a technique the campaign declared forbidden | No |
| `behavior_lost` | The behaviour validator could not prove the attack chain survives | No |
| `detected` | A FATAL fired, or the score went above the threshold with an expected rule firing | No |
| `partial_evasion` | The expected rule stayed quiet, but the result is still FLAGGED | No — the catching rules are recorded |
| `fail_closed_catch` | A coverage gap forbade UNFLAGGED | **No — the tool worked** |
| `bypass` | Syntax valid, constraints honoured, behaviour proven, and TrustSight returned UNFLAGGED | **Yes** |
| `known_bypass_match` | Matches a bypass committed by an earlier campaign at a different version | No — a patch-verification event |
| `harness_error` | Runner crash, TrustSight API failure, or an analysis that exceeded its timeout | No — aborts the campaign above a rate threshold |

`BYPASS_STATUSES` is written as a frozen set containing exactly one member rather
than as an equality test, because the temptation it guards against is someone
adding a second one.

## Order of application

Stages run in sequence and the first refusal ends the attempt. The pre-TrustSight
stages, in order:

1. **Sanitize** → `sanitization_failure`
2. **Deduplicate** → `duplicate` *(before validation and before any charge)*
3. **Syntax** → `syntax_error`
4. **Constraints** → `constraint_violation`
5. **Behaviour** → `behavior_lost`

An attempt that survives all five runs against TrustSight, and the
[Judge](../explanation/design-notes.md) applies the remaining tests in this exact
order:

1. Any earlier terminal status → passthrough.
2. Report contains a **FATAL** finding → `detected`.
3. `coverage_gaps` non-empty (after subtracting [mode gaps](../explanation/design-notes.md)) → `fail_closed_catch`.
4. Score **above** the flag threshold → `detected` if an expected rule fired, `partial_evasion` otherwise.
5. Score **at or below** the threshold, no gaps, no FATAL → `bypass`.

A rediscovered hash is re-labelled `known_bypass_match` after the Judge has run,
so the underlying verdict still determines its `patch_status`.

!!! warning "Order matters, and the order is not arbitrary"

    FATAL is tested before the score because a FATAL finding is a detection
    whatever the arithmetic says. Gaps are tested before the threshold because a
    gap means the tool declined to answer, and an incomplete analysis that
    happens to score low is not a clean result.

## The three statuses people misread

### `fail_closed_catch` is a positive result

Padding a diff so the payload sits past a read bound does not produce a clean
result in TrustSight. It produces an incomplete one, and an incomplete analysis
may never be UNFLAGGED. Counting that as a bypass would score the tool worst
exactly where it behaves best.

These attempts export to `fixtures-gaps/` as regression tests for the fail-closed
layer itself — asserting that the gap *is* recorded and that UNFLAGGED is
forbidden — never to the malicious corpus.

### `partial_evasion` is a granularity metric

The payload was caught, but not by the rule the campaign set out to test. That is
worth recording precisely — the trace names the catching rules with their
severities and weights — but rule-level evasion is not tool-level evasion.

### `behavior_lost` is not "the attempt failed"

It means the harness could not **prove** the payload still works. Sometimes the
payload is genuinely dead. Sometimes it is alive and the validator cannot follow
it. The design accepts the second case explicitly, and
[Lower-Bound Reporting](../explanation/measurement-and-maturity.md) is the
consequence.

## Aborting on harness errors

A campaign whose errors outnumber its measurements is not measuring. After at
least ten attempts, a `harness_error` rate above 20% re-raises the underlying
exception and ends the campaign. Errors before that point are recorded, exported
to `fixtures-robustness/`, and the loop continues — a single crash is a data
point about the tool, not a reason to discard the run.
