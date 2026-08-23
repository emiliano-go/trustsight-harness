---
description: Run the shipped campaign, read the summary it prints, and find the trace behind every number.
---

# Running a Campaign

The repository ships one campaign, `known-bypasses-manual`. It replays eight
recipes drawn from real evasions found against TrustSight, in fully
deterministic manual mode. Running it is the fastest way to see every part of
the pipeline do its job, including the parts that refuse.

```bash
uv run python -m harness campaigns/known-bypasses-manual
```

## What it prints

```json
{
  "campaign": "known-bypasses-manual",
  "attempts": 8,
  "outcomes": {
    "behavior_lost": 3,
    "detected": 4,
    "partial_evasion": 1
  },
  "bypass_rate": {
    "estimate": 0.0,
    "ci_95_wilson": [0.0, 0.434482],
    "denominator": "attempts reaching TrustSight",
    "denominator_value": 5,
    "note": "lower bound (validator is conservative)"
  }
}
```

Four things in that output are worth reading carefully.

**Zero-valued outcomes are omitted from the summary but not from the record.**
The record on disk carries every status in the table, including the zeros.

**The denominator is 5, not 8.** Three attempts were discarded as
`behavior_lost` and never reached TrustSight. Including them would let a
generator lower its own measured bypass rate by emitting garbage.

**The interval is enormous.** Zero bypasses out of five attempts is consistent
with a true rate anywhere up to 43%. That is not a defect in the arithmetic; it
is what five attempts are worth. See
[Measurement and Maturity](../explanation/measurement-and-maturity.md).

**`partial_evasion` is not a bypass.** One recipe evaded the rule the campaign
named in `expected_rules` and was caught by a different one. The record names
the catching rules with their severities and weights.

## What it writes

```
campaigns/known-bypasses-manual/
├── campaign.yml          # the whole configuration, committed before the run
├── record.json           # the whole result
├── traces/
│   ├── 00000.json        # one per attempt
│   ├── 00001.json
│   └── …
└── env/                  # this campaign's own TrustSight data and config
```

Plus, at the repository root, anything the campaign exported:

```
fixtures-out/
├── <hash>.diff           # bypasses, for human review
├── fixtures-gaps/        # fail-closed catches: regression tests for the gap layer
└── fixtures-robustness/  # hangs and crashes
```

Nothing here is ever submitted automatically. See
[Auditing Results](../guides/auditing-results.md).

## Following one attempt

Every number in the record traces back to a file. Take the attempt that was
discarded before TrustSight ever saw it:

```bash
jq '{status, stages}' campaigns/known-bypasses-manual/traces/00003.json
```

```json
{
  "status": "behavior_lost",
  "stages": {
    "sanitization": { "passed": true, "reason": "" },
    "syntax": { "bash_n_old": 0, "bash_n_new": 0, "reason": "" },
    "constraints": { "honored": true, "violated": [] },
    "behavior": {
      "preserved": false,
      "chain": "",
      "reason": "no reachable fetch-to-execution chain",
      "validator_version": "sha256:…"
    }
  }
}
```

The stages run in order and stop at the first refusal. This one passed the
sanitizer and `bash -n`, honoured the campaign's constraints, and then failed to
prove its attack chain; so it never ran against TrustSight, and it is not in
the denominator.

!!! tip "A discarded attempt is a result, not an error"

    `behavior_lost` means the validator could not prove the payload still works.
    Sometimes the payload really is dead. Sometimes it is alive and the
    validator cannot see it; two of the shipped inputs are exactly that, kept
    deliberately. Both are recall failures, and
    [Section 1.5](../explanation/measurement-and-maturity.md) is the reason every
    published count is a lower bound.

## What ran before the first attempt

Before a single attempt is charged for, the harness:

1. resolves the installed TrustSight version and compares it to the declared one;
2. binds TrustSight's data and config directories to campaign-local paths;
3. restores the database to the declared state;
4. analyses the **canary**; a committed benign recipe; and records its score;
5. runs one **API/CLI parity check**, because a record produced by a broken
   instrument is worse than no record.

Any of these failing is a configuration fault (exit 1) or a harness error
(exit 2), never a result.

## Next

[Reading a Record &rarr;](reading-a-record.md)
