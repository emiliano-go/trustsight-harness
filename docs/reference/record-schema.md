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
| `campaign_type` | string | `deterministic` or `stochastic`. |
| `campaign_commit` | string | Git commit hash of `campaign.yml` at run time, or empty if not in git. |
| `environment` | object | The resolved environment descriptor. |
| `generator` | object | Generator type, model, prompt hash, etc. |
| `validator` | object | Behaviour-validator version hash and calibration status. |
| `attempts` | integer | Number of attempts actually recorded. |
| `stop_reason` | string | Why the campaign ended, including early stops. |
| `outcomes` | object | Count per terminal status. |
| `bypass_rate` | object | Wilson-scored binomial proportion over attempts that reached TrustSight. |
| `bypass_hashes` | list | Diff hashes classified as `bypass`. |
| `known_bypass_matches` | list | Rediscovered bypasses, with `patch_status`. |
| `cost` | object | Tokens, API spend, ceiling, wall clock. |

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
| `config_fingerprint` | TrustSight config fingerprint, verified every attempt. |
| `flag_threshold` | The score threshold used by the Judge. |
| `accumulate` | Whether the database was allowed to warm between attempts. |
| `timezone` | `TZ` at run time. |
| `locale` | `LC_ALL`/`LANG` at run time. |
| `canary_check` | `"passed"` if the canary verified. |
| `canary_score` | The canary's committed score. |
| `mode_gaps` | Gaps derived from the canary, subtracted before the gap test. |

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
