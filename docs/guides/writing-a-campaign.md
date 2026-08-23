---
description: Configure campaign.yml, choose a generator, declare constraints, and pre-register stop conditions.
---

# Writing a Campaign

A campaign is a directory under `campaigns/` containing `campaign.yml` and the
assets the generator needs. The directory is the unit of pre-registration:
`attempts`, cost ceiling, and stop conditions are committed before the run so
that post-hoc attempt-count shopping is visible in git history.

## Minimal manual campaign

```yaml
campaign: my-first-campaign
campaign_type: deterministic

environment:
  trustsight_version: "0.13.2"
  trustsight_source: "local-path"
  db_state: "cold"
  flag_threshold: 20

generator:
  type: manual
  directory: manual
  baseline: defaults/baseline.PKGBUILD

prompt:
  prompt_id: fetch-then-execute
  behavior_goal: fetch_then_execute
  expected_rules: ["R001", "R002"]
  forbidden_techniques: {}

attempts: 10
```

Place `.PKGBUILD` files in `campaigns/my-first-campaign/manual/`. Each is
diffed against the baseline and run through the pipeline.

## Choose the campaign type

| Type | Use when | Record implications |
|---|---|---|
| `deterministic` | Every attempt is a committed input; replay produces the same diff hashes. | Verdicts are reproducible for the pinned triple. |
| `stochastic` | LLM or mutation generator; output varies between runs. | Bypass rate is a binomial proportion with Wilson interval. |

A deterministic generator with `environment.accumulate: true` is still
stochastic for verdict purposes, because the database state depends on run
order.

## Declare constraints explicitly

`prompt.forbidden_techniques` is required. Use `{}` for an unconstrained
campaign, but declare it so the record says so. A forbidden technique without a
matching checker is a configuration error; the harness will not run.

## Pre-register stop conditions

```yaml
stop_conditions:
  bypasses: 5
  wall_clock_seconds: 3600
```

Stopping early is recorded in `record.json` under `stop_reason`. Because the
condition is in `campaign.yml`, the decision to stop is part of the committed
configuration, not a judgement made while watching results.

## Generators

- **manual**; static `.PKGBUILD` or `.diff` files.
- **mutation**; semantic-preserving variations of committed bypasses.
- **llm**; OpenAI-compatible provider, with a mandatory `max_cost_usd` ceiling.

See [Campaign Configuration](../reference/campaign-config.md) for the complete
key reference.
