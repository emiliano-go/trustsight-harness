---
description: Every field of record.json, what it measured, and what it is evidence for.
---

# Reading a Record

`record.json` is the whole result of a campaign. Everything in it was measured;
nothing in it was inferred. This page walks the file top to bottom. The formal
field list is in the [Record Schema](../reference/record-schema.md).

## Identity

```json
{
  "harness_version": "1.0.0",
  "campaign": "known-bypasses-manual",
  "campaign_type": "deterministic",
  "campaign_commit": "a1b2c3…"
}
```

`campaign_commit` is the commit that last touched `campaign.yml`. The campaign
file — attempts, spending ceiling, stop conditions — is committed **before** the
run, so choosing to stop early is a decision visible in git history rather than a
judgement made while watching results scroll past.

`campaign_type` is `deterministic` or `stochastic`, and the harness will not let
you mislabel it: a campaign declaring `accumulate: true` is stochastic for verdict
purposes even with a fully deterministic generator, because an accumulating
database makes verdicts depend on run order.

## Environment

```json
"environment": {
  "trustsight_version": "0.13.2",
  "trustsight_source": "local-path",
  "python_version": "3.13",
  "db_state": "cold",
  "config_fingerprint": "sha256:…",
  "flag_threshold": 20,
  "accumulate": false,
  "canary_check": "passed",
  "canary_score": 0,
  "mode_gaps": ["tree_not_analyzed"]
}
```

This is the instrument. Read it before you read any number below it — a bypass
count without the environment that produced it is an anecdote.

`canary_check` and `canary_score` are how you know the database restore actually
happened. A restore that silently did nothing looks exactly like one that worked,
right up until the numbers are published.

`mode_gaps` are coverage gaps the **canary** also produced, so they are a property
of the analysis mode rather than evidence about any attack. The harness analyses
text rather than repositories, so `tree_not_analyzed` appears on every report
including benign ones. They are derived from the canary run and never declared in
a config, so a campaign cannot use the mechanism to discount a gap an attack
actually caused — and they are listed here so you can see exactly what was
excluded. See [Design Notes](../explanation/design-notes.md#mode-gaps-analyze_text-always-reports-tree_not_analyzed).

## Generator and validator

```json
"generator": { "type": "manual", "directory": "manual", "inputs": 8,
               "prompt_id": "fetch-then-execute-manual", "prompt_hash": "sha256:…" },
"validator": { "version_hash": "sha256:…", "calibration": "passed" }
```

`validator.version_hash` is the content hash of `validators/behavior.py`. A change
to the validator is a new instrument, and records are never re-interpreted against
a later one.

`calibration: passed` is load-bearing. No bypass number is publishable from a build
whose calibration suite fails, and the exporter raises rather than writing a fixture
from one.

## Outcomes

```json
"attempts": 8,
"stop_reason": "8 manual inputs exhausted",
"outcomes": {
  "sanitization_failure": 0, "duplicate": 0, "syntax_error": 0,
  "constraint_violation": 0, "behavior_lost": 3, "detected": 4,
  "partial_evasion": 1, "fail_closed_catch": 0, "bypass": 0,
  "known_bypass_match": 0, "harness_error": 0
}
```

Every terminal status appears, including the zeros — an outcome table with
statuses missing invites the reader to assume they were impossible rather than
absent. `stop_reason` says why the loop ended: inputs exhausted, a pre-registered
stop condition, or a cost ceiling.

## The rate

```json
"bypass_rate": {
  "estimate": 0.0,
  "ci_95_wilson": [0.0, 0.434482],
  "denominator": "attempts reaching TrustSight",
  "denominator_value": 5,
  "note": "lower bound (validator is conservative)"
}
```

Four deliberate choices in one object:

- **Wilson, not normal.** Campaigns are small and bypass rates are near zero,
  which is exactly where the normal approximation produces bounds below zero and
  claims a precision it does not have.
- **The denominator is stated, not assumed.** Attempts that never reached
  TrustSight are excluded, and the count is given so you can check the exclusion.
- **The caveat is inside the value.** It travels with the number into whatever
  quotes it, rather than living in documentation the quoter did not read.
- **There is no "effectiveness" field.** See
  [forbidden fields](../reference/record-schema.md#forbidden-fields).

## Bypasses and rediscoveries

```json
"bypass_hashes": ["sha256:…"],
"known_bypass_matches": [
  { "diff_hash": "sha256:…",
    "original_campaign": "fetch-evasion-2026-07",
    "original_trustsight_version": "0.12.0",
    "patch_status": "verified",
    "observed_status": "detected",
    "trustsight_version": "0.13.2" }
]
```

A rediscovered bypass is not waste and not a new find. Run against a newer
TrustSight it answers a question no fresh attempt can — did the patch hold? —
so `patch_status` is `verified` (it is now caught) or `regression` (it is still
open), and it is recorded under its own status so it can never inflate a bypass
count.

At the *same* version there is nothing to learn, so a known hash is a `duplicate`
and is never re-run or re-charged.

## Cost

```json
"cost": { "tokens_in": 0, "tokens_out": 0, "api_cost_usd": 0.0,
          "ceiling_usd": null, "retries": 0, "wall_clock_ms": 1843 }
```

`retries` counts failed calls that were retried — cost honesty includes waste.
`wall_clock_ms` is the campaign's wall clock, not the sum of the attempts; the
gap between them is the harness's own overhead, and a reader comparing two
campaigns is entitled to see it.

For an LLM campaign, `ceiling_usd` is the ceiling the campaign declared before it
started. See [Writing a Campaign](../guides/writing-a-campaign.md).

## Where to go next

- [Record Schema](../reference/record-schema.md) — the complete record format
- [Terminal Statuses](../reference/statuses.md) — what each outcome name means
- [Writing a Campaign](../guides/writing-a-campaign.md) — measure something of your own
