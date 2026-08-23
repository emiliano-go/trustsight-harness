# trustsight-harness

Adversarial measurement harness for [TrustSight](https://github.com/emiliano-go/trustsight).
Turns "an LLM found N bypasses" into a reproducible, auditable, cost-tracked
measurement against a pinned TrustSight build.

```bash
python -m harness campaigns/<name>/     # run a campaign, write a record
python -m harness regression            # replay every committed bypass
```

## What it measures

A **bypass** is exactly this: a diff whose syntax is valid, whose declared
constraints were honoured, whose attack chain is provably intact, and which
TrustSight returned **UNFLAGGED** for (score at or below the threshold, no
coverage gaps, no FATAL finding).

Everything else has its own name:

| Status | Meaning |
|---|---|
| `detected` | A FATAL fired, or the score exceeded the threshold with an expected rule firing. |
| `partial_evasion` | The expected rule stayed quiet, but another rule caught it. |
| `fail_closed_catch` | A coverage gap forbade UNFLAGGED; the tool declined to answer. |
| `behavior_lost` | The harness could not prove the attack chain survives. |
| `syntax_error` | Not a well-formed unified diff, or `bash -n` rejected a side. |
| `constraint_violation` | The diff used a technique the campaign declared forbidden. |
| `duplicate` | Hash already seen in this campaign or recorded at this version. |
| `sanitization_failure` | Null byte, path traversal, or size cap exceeded. |
| `harness_error` | Runner crash, API failure, or analysis timeout. |
| `known_bypass_match` | A committed bypass rediscovered at a different TrustSight version. |

## What it will not do

- **It never executes generated code.** `bash -n` parses; nothing runs.
- **It never fetches a URL a generated PKGBUILD declares.**
- **It never opens your TrustSight database.** Every campaign binds its own data directory.
- **It never opens a pull request.** Fixtures go to a local directory for human review.
- **It never re-implements TrustSight's rules.** It classifies by TrustSight's verdicts.

## Every published count is a lower bound

The behaviour validator is conservative by design. Discarding a live payload
costs one attempt; certifying a dead one puts a fabricated bypass into a record
other people will cite. So it refuses when it cannot prove the chain, and the
true bypass count is at or above what any record reports. The record says so in
the `bypass_rate.note` field itself.

## Reproducibility

TrustSight's score depends on three things: the diff, the config, and the
observation history it accumulates. Every analysis writes to that history, so
each attempt runs against a restored database verified by a canary. The config
fingerprint is re-checked on every attempt rather than once at startup.
`trustsight_version: "latest"` is refused.

## Install and run

```bash
uv sync --locked --all-extras
uv run python -m harness campaigns/known-bypasses-manual
uv run python -m harness regression
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | The run produced a record or report. |
| `1` | Configuration or environment fault. |
| `2` | Harness error. |

The regression gate uses `0` and `2` only.

## Documentation

- [Getting Started](docs/getting-started/index.md): installation, quickstart, and first campaign.
- [Guides](docs/guides/index.md): writing campaigns, CI integration, and auditing results.
- [Reference](docs/reference/index.md): CLI, campaign configuration, record schema, statuses, and exit codes.
- [Self-Security Model](docs/security.md): the boundaries the harness holds itself to.
- [Acceptance Criteria](docs/contributing/acceptance-criteria.md): Section 11 of the specification, mapped to tests.
