---
description: Run the shipped campaign and read the summary in under five minutes.
---

# Quickstart

The fastest way to see the harness work is to replay the committed manual
campaign against the local TrustSight checkout.

## 1. Install

```bash
cd trustsight-harness
uv sync --locked --all-extras
```

This installs the harness and the local TrustSight build it is configured to
measure. The `--locked` flag means the same dependencies the record was produced
with; without it, the measurement is not reproducible.

## 2. Run the shipped campaign

```bash
uv run python -m harness campaigns/known-bypasses-manual
```

You will see something like:

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

A zero bypass rate is a real result: on this TrustSight version, the shipped
recipes were caught, partially caught, or could not be proven to still carry a
live chain. The record holds the evidence.

## 3. Read one trace

```bash
cat campaigns/known-bypasses-manual/traces/00000.json
```

Each trace links one diff to one TrustSight report. It contains only pipeline
output; it does not explain *why* a regex matched. The diff and the report are
the evidence.

## 4. Read the record

```bash
cat campaigns/known-bypasses-manual/record.json
```

`record.json` is the whole campaign result. It includes the environment
descriptor, the generator description, every outcome count, the bypass rate with
a Wilson interval, and the list of bypass hashes. See
[Reading a Record](reading-a-record.md) for a field-by-field walkthrough.

## Next steps

- [Run a campaign with a different configuration](running-a-campaign.md)
- [Write your own campaign](../guides/writing-a-campaign.md)
- [Understand the terminal statuses](../reference/statuses.md)
