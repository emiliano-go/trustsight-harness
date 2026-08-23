---
description: Every key of campaign.yml, its type, whether it is required, and what the loader refuses.
---

# Campaign Configuration

`campaign.yml` is the whole configuration of a campaign. It is validated
strictly: an unknown top-level key is a `ConfigError`, not a comment. The file is
committed **before** the run, so attempts, ceiling and stop conditions are
pre-registered and post-hoc attempt-count shopping is visible in git history.

## A complete example

```yaml
campaign: fetch-evasion-2026-08
campaign_type: stochastic

environment:
  trustsight_version: "0.13.2"
  trustsight_source: "local-path"
  db_state: "cold"
  flag_threshold: 20

generator:
  type: llm
  provider: kimi
  model: kimi-k3
  max_cost_usd: 20.00

prompt:
  prompt_id: fetch-then-execute-v3
  text: |
    …
  behavior_goal: fetch_then_execute
  expected_rules: ["R001", "R002", "X009"]
  forbidden_techniques:
    direct_curl: '(?:\A|[;&|]|\n)\s*curl\b'

attempts: 200

stop_conditions:
  bypasses: 10
  wall_clock_seconds: 7200
```

## Top-level keys

| Key | Type | Required | Meaning |
|---|---|---|---|
| `campaign` | string | **yes** | The campaign's name; appears in the record and in fixture provenance. |
| `campaign_type` | `deterministic` \| `stochastic` | **yes** | How the results may be compared. Anything else is refused. |
| `environment` | mapping | **yes** | See [Record Schema &rarr; environment](record-schema.md#environment). |
| `generator` | mapping | **yes** | See [Writing a Campaign &rarr; generators](../guides/writing-a-campaign.md#generators). |
| `prompt` | mapping | no* | The behaviour goal, expected rules and constraints. |
| `attempts` | integer | **yes** | The upper bound on attempts. |
| `stop_conditions` | mapping | no | Pre-registered early stops. |

\* `prompt` may be omitted only if you also omit `forbidden_techniques`, which
you cannot; see below.

## `prompt`

| Key | Type | Required | Meaning |
|---|---|---|---|
| `prompt_id` | string | no | A stable label for the prompt; recorded alongside its hash. |
| `text` | string | for LLM | The prompt itself. Its SHA-256 goes in the record. |
| `behavior_goal` | string | no | Defaults to `fetch_then_execute`, the only goal implemented. |
| `expected_rules` | list of strings | no | The rule IDs the campaign set out to test. |
| `forbidden_techniques` | mapping | **yes** | Technique name → regex. |

### `forbidden_techniques` is mandatory, even when empty

```yaml
forbidden_techniques: {}
```

An unconstrained campaign has to say so. Leaving the key out would let a reader
infer whichever answer suits them, and the record is the only thing anyone will
read later.

A technique **must** map to a checker. A name with an empty or missing pattern is
a `CheckerError`, because a forbidden technique nobody can check is a promise the
record cannot keep. Patterns are compiled with `re.MULTILINE` and matched against
the *new* PKGBUILD text before TrustSight runs.

!!! tip "Why constraints exist at all"

    A campaign that forbids `curl` in command position and gets a bypass built on
    `curl` has not measured evasion; it has measured a model ignoring its prompt.
    Constraint checking makes that a recorded outcome
    (`constraint_violation`) instead of a silent contaminant.

## `stop_conditions`

| Key | Type | Meaning |
|---|---|---|
| `bypasses` | integer | Stop once this many bypasses have been recorded. |
| `wall_clock_seconds` | integer | Stop once the campaign has run this long. |

Both are checked at the top of each attempt, and the reason is written to
`record.stop_reason`. Declaring them in the committed file is the point: an early
stop is then a decision in git history rather than a judgement made while
watching results.

## Refusals

The loader refuses, with exit code 1, when:

| Condition | Message |
|---|---|
| Unknown top-level key | `unknown campaign keys: [...]` |
| Missing `campaign`, `environment`, `generator` or `attempts` | `campaign.<key> is required` |
| `campaign_type` is neither value | `campaign_type must be 'deterministic' or 'stochastic'` |
| `forbidden_techniques` absent | `declare {} explicitly for an unconstrained campaign` |
| A forbidden technique has no pattern | `forbidden technique 'x' has no checker` |
| An LLM generator without `max_cost_usd` | `llm campaigns require generator.max_cost_usd` |
| `accumulate: true` with `campaign_type: deterministic` | `accumulate makes verdicts order-dependent` |

That last one is worth reading twice. A campaign may model a warming database,
but it cannot then call itself deterministic: attempt *i* teaches TrustSight the
URL that attempt *i+1* is about to be scored on, so the verdicts depend on run
order even when the generator does not.
