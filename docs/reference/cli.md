---
description: Complete reference for python -m harness; campaigns, the regression gate, coverage and the benign scan.
---

# CLI Reference

The harness has four commands. One config, one record, one command each.

```bash
python -m harness <campaign-directory> [--dump-inputs DIR]
python -m harness sweep [--jobs N] [--match GLOB]
python -m harness regression [--environment PATH]
python -m harness coverage
python -m harness benign --corpus <dir> [--sample N]
```

Under `uv`, prefix with `uv run`:

```bash
uv run python -m harness campaigns/known-bypasses-manual
```

---

## `python -m harness <campaign-directory>`

Runs one campaign and writes its record.

### Arguments

| Argument | Required | Meaning |
|---|---|---|
| `target` | yes | A directory containing `campaign.yml`. |
| `--dump-inputs DIR` | no | Write every generated input to `DIR` and exit, without running. Audits what the manifest renders to. |

### What happens before the first attempt

1. The behaviour validator's **calibration suite** runs. A failure refuses the
   campaign with exit 1; no bypass number is publishable from a build that
   cannot tell a live chain from a dead one.
2. `campaign.yml` is loaded and **strictly validated**. An unknown key is a
   mistake worth stopping for, not a comment.
3. The declared TrustSight version is compared against the installed one.
4. TrustSight's data and config directories are bound to campaign-local paths.
5. The database is restored, the **canary** is analysed, and its score is recorded.
6. One **API/CLI parity check** runs.

### Output

A JSON summary on stdout; campaign name, attempt count, non-zero outcomes, and
the bypass rate with its interval:

```json
{
  "campaign": "known-bypasses-manual",
  "attempts": 8,
  "outcomes": { "behavior_lost": 3, "detected": 4, "partial_evasion": 1 },
  "bypass_rate": { "estimate": 0.0, "ci_95_wilson": [0.0, 0.434482],
                   "denominator": "attempts reaching TrustSight",
                   "denominator_value": 5,
                   "note": "lower bound (validator is conservative)" }
}
```

The summary omits zero-valued outcomes; `record.json` keeps all of them.

### Files written

| Path | Contents |
|---|---|
| `<campaign>/record.json` | The complete campaign record |
| `<campaign>/evidence.jsonl` | One JSON trace per attempt, with the diff embedded for bypasses |
| `<campaign>/inputs.yml` | The recipes as data, one cell per attempt |
| `<campaign>/template.PKGBUILD` | The shared skeleton, when the cells are templated |
| `<campaign>/env/` | The campaign's own TrustSight data and config directories; relocate to tmpfs with `HARNESS_ENV_ROOT` |
| `<campaign>/thinking/` | LLM reasoning logs, when the generator produces them |
| `fixtures-out/` | Exported bypasses, gap fixtures and robustness finds |

---

## `python -m harness sweep`

Runs every campaign under `campaigns/`, in parallel where asked. The
campaigns are independent — each binds its own database and writes only
inside its own directory — so a re-baseline is a worker pool, not a loop.

| Argument | Required | Meaning |
|---|---|---|
| `--jobs N` \| `auto` | no | Concurrent campaigns (default `1`; `auto` caps at 4). |
| `--match GLOB` | no | Only campaigns whose name matches; repeatable. |

Each campaign still verifies its own environment and canary before its first
attempt. A campaign that fails is reported in the summary and does not stop
the others; the command exits 2 if any failed, 0 otherwise.

```bash
uv run python -m harness sweep --jobs auto
# {"campaigns": 74, "attempts": 1402, "bypasses": 0, "bypassing": []}
```

---

## `python -m harness regression`

Replays every bypass committed by every campaign in `campaigns/` against the
current environment.

### Arguments

| Argument | Required | Meaning |
|---|---|---|
| `--environment PATH` | no | Environment YAML. Defaults to `defaults/environment.yml`. |
| `--jobs N` \| `auto` | no | Replay workers (default `1`; `auto` caps at 4). Each worker binds its own database; the merged report is identical to the serial one. |
| `--no-cache` | no | Ignore and do not write `regression/cache.jsonl`. A result is cached only when every verdict input is in the key (diff, instrument pin, config fingerprint, validator and Judge sources, canary gaps, threshold, database state). Degraded results are never cached. |

### Behaviour

For each committed bypass hash: locate its diff by **re-hashing** the embedded
diff in `evidence.jsonl` (never by filename), restore the database, re-analyse,
and classify.

- Still UNFLAGGED → **open**
- A positive finding → **closed**, with the closing version recorded
- Fails `bash -n` now → **unreplayable**, with the reason
- Analysis stage failed (`stage_degraded`, the tokenizer sandbox timing out
  under load) → **degraded**, retried once serially, never counted closed

The gate also replays the canary and one API/CLI parity check per environment, so
a "closed" bypass is never an artefact of a broken harness.

!!! tip "A full replay writes gigabytes"

    Each replay restores the database before the attempt, and a restore is
    fsync-heavy. Point `HARNESS_ENV_ROOT` at a tmpfs to keep the churn out of
    the disk (the committed tree is untouched; the scratch is keyed per work
    root):

    ```bash
    HARNESS_ENV_ROOT=/dev/shm/trustsight-harness uv run python -m harness regression --jobs auto
    ```

### Output

```
Of 1277 known bypasses, 1276 closed, 1 open as of 0.18.0.
```

and `regression/report.json` with the per-bypass detail.

!!! note "This is a report, not a verdict"

    Improvement and regression are both data. Whether "0 open" is good news is a
    maintainer's call, made in a review with the report attached.

### Exit codes

The regression gate uses **0 and 2 only**. A caller scripting it should never
have to distinguish "misconfigured" from "broken" to know whether a report
exists. A missing environment file is therefore exit 2, not exit 1.

---

## `python -m harness coverage`

Maps every campaign to the rules it sets out to test, against TrustSight's own
rule taxonomy, and writes `coverage/report.json`.

The harness is adversarial, not exhaustive. This makes the untested surface a
number: of 212 rules, how many a campaign names, grouped by category, with the
rules a cold `analyze_text` campaign *cannot* reach named and explained (the
adoption and composition rules need a corpus cycle or recorded observation).

```bash
uv run python -m harness coverage
# 25 of 212 rules targeted by 74 campaigns; 187 untargeted, 11 with a reason.
```

---

## `python -m harness benign`

Scans a directory of benign `*.diff` files and reports the **false-positive**
rate: how many a healthy update causes TrustSight to flag. This is the other
half of the measurement every campaign leaves out.

It is deliberately not a campaign. A benign update carries no fetch-to-execute
chain, so the behaviour validator would discard it as `behavior_lost` before
TrustSight saw it; and an unflagged benign diff is not a bypass, so the
exporter must not file it as one. This path calls `trustsight.analysis.scan_diff`
directly, with the host's pacman answer frozen to the cold-machine value so the
number is reproducible.

### Arguments

| Argument | Required | Meaning |
|---|---|---|
| `--corpus DIR` | yes | Directory of benign `*.diff` files, searched recursively. |
| `--sample N` | no | Scan every Nth diff (default: all). Do not compare a sample's rate to a whole-corpus one. |
| `--environment PATH` | no | Environment YAML. Defaults to `defaults/environment.yml`. |

### Output

`benign/report.json`, plus a one-line summary:

```
15 of 186 benign diffs flagged at threshold 20 (rate 0.0806).
```

Against TrustSight's own 3,739-diff corpus the whole-run figure is ~7.8%, the
same order as the tool's published calibration.

---

## Exit codes

| Code | Meaning |
|---|---|
| **0** | The run produced a record or a report |
| **1** | A configuration or environment fault the operator must fix *(campaigns only)* |
| **2** | A harness error |

Whether the numbers are good news is never encoded in an exit code. See
[Exit Codes](exit-codes.md).
