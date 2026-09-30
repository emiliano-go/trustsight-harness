# trustsight-harness

Adversarial measurement harness for [TrustSight](https://github.com/emiliano-go/trustsight).
Turns "an LLM found N bypasses" into a reproducible, auditable, cost-tracked
measurement against a pinned TrustSight build.

<p align="center">
  <a href="https://www.python.org/downloads/">
    <img src="https://img.shields.io/badge/Python-3.12%2B-3776AB?logo=python&logoColor=white&style=for-the-badge" alt="Python">
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/License-MIT-10AC84?style=for-the-badge" alt="License">
  </a>
  <a href="https://deepwiki.com/emiliano-go/trustsight-harness">
    <img src="https://img.shields.io/badge/Ask-DeepWiki-007ec6?style=for-the-badge" alt="Ask DeepWiki">
  </a>
  <a href="https://github.com/emiliano-go/trustsight-harness/actions/workflows/ci.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/emiliano-go/trustsight-harness/ci.yml?branch=master&style=for-the-badge&logo=github&label=CI" alt="CI">
  </a>
</p>

## Two ways to run

From a checkout, pinned to a sibling TrustSight:

```bash
git clone https://github.com/emiliano-go/trustsight-harness
cd trustsight-harness
uv sync --locked --all-extras
uv run python -m harness campaigns/known-bypasses-manual
```

From the container, which carries a pinned TrustSight checkout and needs no
sibling:

```bash
docker run --rm ghcr.io/emiliano-go/trustsight-harness:latest regression
```

The commands:

```bash
python -m harness campaigns/<name>/     # run a campaign, write a record
python -m harness regression            # replay every committed bypass
python -m harness coverage              # which rules the suite does and does not probe
python -m harness benign --corpus <dir> # false-positive rate over a benign corpus
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
| `bypass` | Syntax valid, constraints honoured, behaviour proven, and TrustSight returned UNFLAGGED. |
| `behavior_lost` | The harness could not prove the attack chain survives. |
| `syntax_error` | Not a well-formed unified diff, or `bash -n` rejected a side. |
| `constraint_violation` | The diff used a technique the campaign declared forbidden. |
| `duplicate` | Hash already seen in this campaign or recorded at this version. |
| `sanitization_failure` | Null byte, path traversal, or size cap exceeded. |
| `harness_error` | Runner crash, API failure, or analysis timeout. |
| `known_bypass_match` | A committed bypass rediscovered at a different TrustSight version. |

## How a campaign runs

Each attempt goes through fixed stages, and the record keeps the outcome of every
one of them:

1. **Generate.** A manual campaign replays committed diffs; a mutation or LLM
   campaign produces new ones under a declared cost ceiling.
2. **Validate.** `bash -n` parses the diff and never executes it. The declared
   forbidden techniques are checked. The behaviour validator proves a
   fetch-to-execution chain survives, or discards the attempt as `behavior_lost`.
3. **Analyse.** The diff goes through TrustSight's public API, against a
   campaign-local database restored and canary-verified before the attempt.
4. **Judge.** The verdict is classified by a fixed matrix: FATAL, coverage gap,
   expected rule, or neither. The harness never forms its own opinion of the diff.
5. **Record and export.** The attempt is written to `traces/`, the record to
   `record.json`, and a bypass or a gap to `fixtures-out/` for human review.

## What ships

- **A campaign suite.** 26 committed campaigns: the eight known-bypass recipes,
  per-rule probes for the rules added since TrustSight 0.15.7 (C011, C012, C013,
  R152, R078, R091, R099, R104, H096, H097, X024, X025), the Atomic Arch
  build-time and install-hook shapes, and the wave-3 obfuscated variants. Every
  campaign pins TrustSight 0.17.1 and is deterministic.
- **A regression gate.** `python -m harness regression` replays every committed
  bypass and reports how many are still open, with the closing version recorded.
- **A coverage report.** `python -m harness coverage` maps the campaigns to
  TrustSight's rule taxonomy, so the untested surface is a number. 20 of 191
  rules are targeted, and the ones a cold campaign cannot reach are named with
  the reason.
- **A false-positive scan.** `python -m harness benign --corpus <dir>` reports the
  benign flag rate with a Wilson interval, the other side of the measurement.
- **An MCP server.** `harness-mcp` exposes the campaign, regression, analysis and
  reference tools to an agent, with the same path confinement as the CLI.

## Container

`ghcr.io/emiliano-go/trustsight-harness` carries both the harness and a pinned
TrustSight checkout, so it measures exactly the commit CI pins
(`.github/trustsight-commit`). The entrypoint is `python -m harness`, so every
command above is an argument:

```bash
docker run --rm ghcr.io/emiliano-go/trustsight-harness:latest coverage
docker run --rm ghcr.io/emiliano-go/trustsight-harness:latest regression
```

Mount a directory over the tree a command writes to keep its report, for example
`-v "$PWD/out:/app/trustsight-harness/regression"`.

## What it will not do

- **It never executes generated code.** `bash -n` parses; nothing runs.
- **It never fetches a URL a generated PKGBUILD declares.**
- **It never opens your TrustSight database.** Every campaign binds its own data directory.
- **It never reads outside a campaign's tree.** A path in `campaign.yml` is confined to its root.
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
`trustsight_version: "latest"` is refused. CI and the container read the pinned
TrustSight commit from one file, so they cannot measure different trees.

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
- [Acceptance Criteria](docs/acceptance.md): the specification, mapped to tests.

## License

MIT. See [LICENSE](LICENSE).
