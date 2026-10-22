---
description: The complete schema for record.json, field by field, including the fields the specification forbids.
---

# Record Schema

`record.json` is the committed result of a campaign. Every field is either
measured directly or derived from committed artifacts. The specification
forbids derived aggregates such as "effectiveness" or "robustness_score"; the
harness raises if any of those leak into a record.

## Top-level fields

| Field | Type | Meaning |
|---|---|---|
| `harness_version` | string | Harness version that produced the record. |
| `campaign` | string | Campaign name, from `campaign.yml`. |
| `campaign_type` | string | `deterministic`, `stochastic` or `rule-probe`. |
| `campaign_commit` | string | Git commit hash of `campaign.yml` at run time, or empty if not in git. |
| `environment` | object | The resolved environment descriptor. |
| `generator` | object | Generator type, model, prompt hash, etc. |
| `validator` | object | Behaviour-validator version hash and calibration status. |
| `attempts` | integer | Number of attempts actually recorded. |
| `stop_reason` | string | Why the campaign ended, including early stops. |
| `outcomes` | object | Count per terminal status. |
| `bypass_rate` | object | Wilson-scored binomial proportion over attempts that reached TrustSight (every `bypass` verdict). |
| `bypasses` | integer | Every attempt whose status is `bypass`. The hard number; it does not shrink for a configuration hole. |
| `bypasses_full` | integer | The subset whose layer audit classified FULL: every assurance layer was exercised (L9 included) and none fired. |
| `conditional_bypasses` | object | Remediation map: reason (`cold_state`, `lane_disabled`, `config`) → number of bypasses carrying it. A bypass counts once per distinct reason. `shape_inapplicable` never appears here. |
| `bypass_hashes` | list | Diff hashes classified as `bypass`. |
| `known_bypass_matches` | list | Rediscovered bypasses, with `patch_status`. |
| `cost` | object | Tokens, API spend, ceiling, wall clock. |
| `cell_coverage` | object | The primary metric: unique `(rule, shape)` cells this run filled, plus the shared grid's open/total counts. |
| `duplicate_rate` | number \| null | Semantic duplicates over attempts that reached dedup; null when none did. The Goodhart canary for generator exploration. |
| `dedup_savings` | object \| null | Analyses semantic dedup avoided (`analyses_avoided`) over attempts that reached it. |
| `minimization_spend` | object \| null | Minimizer analyses, attempts and partials. Kept off the measured path; reported only so the cost is visible. |
| `probe` | object \| absent | Rule probes only: expected rules, cells measured, every rule that fired and any expected rule that did not. |

## `environment`

See [Campaign Configuration](campaign-config.md) for how these are declared.

| Field | Meaning |
|---|---|
| `trustsight_version` | Exact TrustSight version pinned by the campaign. |
| `trustsight_source` | `pypi`, `git-sha`, or `local-path`. |
| `python_version` | Python major.minor. |
| `db_state` | `cold`, `seeded`, or `snapshot`. |
| `seed_sha256` | Required when `db_state` is `seeded`. |
| `db_snapshot` | Required when `db_state` is `snapshot`. |
| `ioc_baseline` | Path to a federation IOC baseline imported into every restored database, so a campaign can assert its `ioc_matches`. Relative to the repository root. |
| `config_fingerprint` | TrustSight config fingerprint, verified every attempt. |
| `flag_threshold` | The score threshold used by the Judge. |
| `accumulate` | Whether the database was allowed to warm between attempts. |
| `timezone` | `TZ` at run time. |
| `locale` | `LC_ALL`/`LANG` at run time. |
| `canary_check` | `"passed"` if the canary verified. |
| `canary_score` | The canary's committed score. |
| `mode_gaps` | Gaps derived from the canary, subtracted before the gap test. |
| `aur_lookup` | `frozen-empty` when TrustSight's AUR lookups were answered from the frozen empty reply (the hermetic default), `live` otherwise. |

## Layer audit

Each `bypass` trace in `evidence.jsonl` carries `trustsight.layer_audit`:

| Field | Meaning |
|---|---|
| `exercised` | Layer ids with readable, applicable evidence, plus `L9` only when the optional build lane ran. |
| `not_exercised` | Layer id → `cold_state`, `lane_disabled`, `shape_inapplicable` or `config`. |
| `classification` | `full` when no conditional reason remains; `conditional` otherwise. |
| `conditional_count` | Number of layers carrying a conditional reason. |
| `conditional_reasons` | The conditional subset of `not_exercised`. |

The audit is a projection of the report's own `layers` object plus the run's
recorded configuration. It never infers traversal from a path. A
`shape_inapplicable` layer is not a blind sensor and never makes a bypass
conditional; `cold_state`, `lane_disabled` and `config` do.

## `bypass_rate`

| Field | Meaning |
|---|---|
| `estimate` | `bypasses / reached_trustsight`. |
| `ci_95_wilson` | 95% Wilson score interval. |
| `denominator` | Always `"attempts reaching TrustSight"`. |
| `denominator_value` | The integer denominator. |
| `note` | `"lower bound (validator is conservative)"`. |

## Forbidden fields

The harness refuses to write any of the following: `effectiveness`,
`robustness_score`, `grade`, `rating`, `verdict_summary`, `overall`, `trend`,
`improvement`, `cross_version`. These aggregate or judge beyond the record.
