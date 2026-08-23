# trustsight-harness

Turns "an LLM found N bypasses" into a reproducible, auditable, cost-tracked
measurement against a pinned [TrustSight](https://github.com/emiliano-go/trustsight)
build.

```bash
python -m harness campaigns/<name>/     # run a campaign, write a record
python -m harness regression            # replay every committed bypass
```

## What it measures

A **bypass** is one thing and nothing else: a diff whose syntax is valid,
whose constraints were honoured, whose attack chain is provably intact, and
which TrustSight returned **UNFLAGGED** for - score at or below the
threshold, no coverage gaps, no FATAL finding.

Everything else has its own name. Evading the expected rule while tripping
another is a `partial_evasion`. Evading detection by pushing the payload
past a read bound is a `fail_closed_catch` - the tool declining to answer,
which is the design working, recorded as a positive result and exported as a
regression test for the fail-closed layer.

## What it will not do

- **It never executes generated code.** `bash -n` parses; nothing runs. No
  container, no sandbox, no "just this once".
- **It never fetches a URL a generated PKGBUILD declares.**
- **It never opens your TrustSight database.** Every campaign binds its own.
- **It never opens a pull request.** Fixtures go to a local directory for a
  human to review, classify and submit.
- **It never re-implements TrustSight's rules.** It classifies by
  TrustSight's verdicts.

## Every published count is a lower bound

The behaviour validator is conservative on purpose. Discarding a live
payload costs one attempt; certifying a dead one puts a fabricated bypass
into a record other people will cite. So it refuses when it cannot prove the
chain, and the true bypass count is at or above what any record reports.
The record says so in the field itself.

## Reproducibility

TrustSight's score is a function of the diff, the config, **and the
observation history it accumulates** - and every analysis writes to that
history. So each attempt runs against a restored database, verified by a
canary whose score is committed, with the config fingerprint re-checked on
every attempt rather than once at startup. `trustsight_version: "latest"` is
a configuration error.

## Running it

```bash
uv sync --locked --all-extras
uv run python -m harness campaigns/known-bypasses-manual
uv run python -m harness regression
```

Exit codes: `0` the run produced a record or a report, `1` a configuration
fault the operator must fix, `2` a harness error. The regression gate uses
`0` and `2` only - a caller scripting it should never have to distinguish
"misconfigured" from "broken" to know whether a report exists.

## Documentation

- [docs/contributing/acceptance-criteria.md](docs/contributing/acceptance-criteria.md) - Section 11, with the test that
  checks each item, and where the behaviour validator stops.
- [docs/explanation/design-notes.md](docs/explanation/design-notes.md) - where the implementation
  had to decide something the specification did not settle, and where
  reality contradicted it.
